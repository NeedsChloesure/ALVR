use crate::{
    bitrate::BitrateManager,
    hand_gestures::HandGestureManager,
    input_mapping::ButtonMappingManager,
    sockets::WelcomeSocket,
    statistics::StatisticsManager,
    tracking::{self, TrackingManager},
    ConnectionContext, ServerCoreEvent, ViewsConfig, FILESYSTEM_LAYOUT, SESSION_MANAGER,
};
use alvr_adb::{WiredConnection, WiredConnectionStatus};
use alvr_common::{
    con_bail, dbg_connection, debug, error,
    glam::{Quat, UVec2, Vec2, Vec3},
    info,
    once_cell::sync::Lazy,
    parking_lot::{Condvar, Mutex, RwLock},
    settings_schema::Switch,
    warn, AnyhowToCon, ConResult, ConnectionError, ConnectionState, LifecycleState, Pose,
    BUTTON_INFO, CONTROLLER_PROFILE_INFO, QUEST_CONTROLLER_PROFILE_PATH,
};
use alvr_events::{AdbEvent, ButtonEvent, EventType};
use alvr_packets::{
    ClientConnectionResult, ClientControlPacket, ClientListAction, ClientStatistics,
    NegotiatedStreamingConfig, RealTimeConfig, ReservedClientControlPacket, ServerControlPacket,
    Tracking, VideoPacketHeader, AUDIO, HAPTICS, STATISTICS, TRACKING, VIDEO,
};
use alvr_session::{
    BodyTrackingBDConfig, BodyTrackingSinkConfig, CodecType, ControllersEmulationMode, FrameSize,
    H264Profile, OpenvrConfig, SessionConfig, Settings, SocketProtocol,
};
use alvr_sockets::{
    PeerType, ProtoControlSocket, StreamSocketBuilder, CONTROL_PORT, KEEPALIVE_INTERVAL,
    KEEPALIVE_TIMEOUT, WIRED_CLIENT_HOSTNAME,
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering as AtomicOrdering},
        mpsc::RecvTimeoutError,
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

const RETRY_CONNECT_MIN_INTERVAL: Duration = Duration::from_secs(1);
const HANDSHAKE_ACTION_TIMEOUT: Duration = Duration::from_secs(2);
pub const STREAMING_RECV_TIMEOUT: Duration = Duration::from_millis(500);
const REAL_TIME_UPDATE_INTERVAL: Duration = Duration::from_secs(1);

const MAX_UNREAD_PACKETS: usize = 10; // Applies per stream

static HANDSHAKE_LOOP_ITERATION: AtomicU64 = AtomicU64::new(0);
static CONNECTION_ATTEMPT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn stream_protocol_desc(protocol: &SocketProtocol) -> &'static str {
    match protocol {
        SocketProtocol::Udp => "UDP",
        SocketProtocol::Tcp => "TCP",
    }
}

// The game audio sample rate is part of the negotiated streaming config (the client needs it to
// configure its audio output). Computing it enumerates audio devices and creates virtual audio
// cables, which can take hundreds of milliseconds. The client only waits 500ms for the stream
// config after accepting the control connection, so this value is computed ahead of time (while the
// handshake loop is idle) and only recomputed when the audio settings change.
// Fingerprint of the audio settings the sample rate was computed from, together with the computed
// value. The value is `None` when the audio setup failed for those settings, which stops the idle
// loop from repeatedly enumerating audio devices (and logging) for a broken configuration.
type GameAudioSampleRateCache = Option<(String, Option<u32>)>;

static GAME_AUDIO_SAMPLE_RATE: Lazy<Mutex<GameAudioSampleRateCache>> =
    Lazy::new(|| Mutex::new(None));

fn audio_settings_fingerprint(
    game_audio: &impl serde::Serialize,
    microphone: &impl serde::Serialize,
) -> String {
    format!(
        "{}|{}",
        serde_json::to_string(game_audio).unwrap_or_else(|e| format!("<error: {e}>")),
        serde_json::to_string(microphone).unwrap_or_else(|e| format!("<error: {e}>")),
    )
}

#[cfg(not(target_os = "linux"))]
fn compute_game_audio_sample_rate(settings: &Settings) -> ConResult<u32> {
    let Switch::Enabled(game_audio_config) = &settings.audio.game_audio else {
        info!("[AUDIO] game audio is disabled, using sample rate 0");

        return Ok(0);
    };

    let setup_start = Instant::now();

    let step_start = Instant::now();
    let game_audio_device =
        alvr_audio::AudioDevice::new_output(game_audio_config.device.as_ref()).to_con()?;
    info!(
        "[AUDIO] opened the game audio output device in {:?}",
        step_start.elapsed()
    );

    if let Switch::Enabled(microphone_config) = &settings.audio.microphone {
        let step_start = Instant::now();
        let (sink, source) =
            alvr_audio::AudioDevice::new_virtual_microphone_pair(microphone_config.devices.clone())
                .to_con()?;
        info!(
            "[AUDIO] created the virtual microphone pair in {:?}",
            step_start.elapsed()
        );

        if matches!(
            microphone_config.devices,
            alvr_session::MicrophoneDevicesConfig::VAC
                | alvr_session::MicrophoneDevicesConfig::VBCable
        ) {
            // VoiceMeeter and Custom devices may have arbitrary internal routing.
            // Therefore, we cannot detect the loopback issue without knowing the routing.
            if alvr_audio::is_same_device(&game_audio_device, &sink)
                || alvr_audio::is_same_device(&game_audio_device, &source)
            {
                con_bail!("Game audio and microphone cannot point to the same device!");
            }
        }
        // else:
        // Stream played via VA-CABLE-X will be directly routed to VA-CABLE-X's virtual microphone.
        // Game audio will loop back to the game microphone if they are set to the same VA-CABLE-X device.
    }

    let step_start = Instant::now();
    let sample_rate = game_audio_device.input_sample_rate().to_con()?;
    info!(
        "[AUDIO] the game audio sample rate is {sample_rate} (queried in {:?}, total audio setup in {:?})",
        step_start.elapsed(),
        setup_start.elapsed(),
    );

    Ok(sample_rate)
}

#[cfg(target_os = "linux")]
fn compute_game_audio_sample_rate(settings: &Settings) -> ConResult<u32> {
    Ok(
        if matches!(&settings.audio.game_audio, Switch::Enabled(_)) {
            44100
        } else {
            0
        },
    )
}

fn cached_game_audio_sample_rate(settings: &Settings) -> ConResult<u32> {
    let fingerprint =
        audio_settings_fingerprint(&settings.audio.game_audio, &settings.audio.microphone);

    if let Some((cached_fingerprint, cached_sample_rate)) = &*GAME_AUDIO_SAMPLE_RATE.lock() {
        if cached_fingerprint == &fingerprint {
            if let Some(sample_rate) = cached_sample_rate {
                return Ok(*sample_rate);
            }
        } else {
            info!("[AUDIO] the audio settings changed, recomputing the game audio sample rate");
        }
    }

    let start = Instant::now();
    let result = compute_game_audio_sample_rate(settings);

    match &result {
        Ok(sample_rate) => {
            *GAME_AUDIO_SAMPLE_RATE.lock() = Some((fingerprint, Some(*sample_rate)));

            if start.elapsed() > Duration::from_millis(50) {
                info!(
                    "[AUDIO] computing the game audio sample rate took {:?}",
                    start.elapsed()
                );
            }
        }
        Err(_) => {
            *GAME_AUDIO_SAMPLE_RATE.lock() = Some((fingerprint, None));
        }
    }

    result
}

// Computes the sample rate up front, while nothing is waiting for it. An audio configuration that
// cannot be set up is only reported once, not on every idle iteration.
fn warm_game_audio_sample_rate(settings: &Settings) -> ConResult<()> {
    let fingerprint =
        audio_settings_fingerprint(&settings.audio.game_audio, &settings.audio.microphone);

    if let Some((cached_fingerprint, _)) = &*GAME_AUDIO_SAMPLE_RATE.lock() {
        if cached_fingerprint == &fingerprint {
            return Ok(());
        }
    }

    cached_game_audio_sample_rate(settings).map(|_| ())
}

fn client_control_packet_desc(packet: &ClientControlPacket) -> &'static str {
    match packet {
        ClientControlPacket::PlayspaceSync(_) => "PlayspaceSync",
        ClientControlPacket::RequestIdr => "RequestIdr",
        ClientControlPacket::KeepAlive => "KeepAlive",
        ClientControlPacket::StreamReady => "StreamReady",
        ClientControlPacket::ViewsConfig(_) => "ViewsConfig",
        ClientControlPacket::Battery(_) => "Battery",
        ClientControlPacket::Buttons(_) => "Buttons",
        ClientControlPacket::Log { .. } => "Log",
        _ => "other",
    }
}

pub struct VideoPacket {
    pub header: VideoPacketHeader,
    pub payload: Vec<u8>,
}

fn align32(value: f32) -> u32 {
    ((value / 32.).floor() * 32.) as u32
}

fn is_streaming(client_hostname: &str) -> bool {
    SESSION_MANAGER
        .read()
        .client_list()
        .get(client_hostname)
        .is_some_and(|c| c.connection_state == ConnectionState::Streaming)
}

pub fn contruct_openvr_config(session: &SessionConfig) -> OpenvrConfig {
    let old_config = session.openvr_config.clone();
    let settings = session.to_settings();

    let mut controller_is_tracker = false;
    let mut controller_profile = 0;
    let mut use_separate_hand_trackers = false;
    let controllers_enabled = if let Switch::Enabled(config) = settings.headset.controllers {
        controller_is_tracker =
            matches!(config.emulation_mode, ControllersEmulationMode::ViveTracker);
        // These numbers don't mean anything, they're just for triggering SteamVR resets.
        // Gaps are included in the numbering to make adding other controllers
        // a bit easier though.
        controller_profile = match config.emulation_mode {
            ControllersEmulationMode::RiftSTouch => 0,
            ControllersEmulationMode::Quest2Touch => 1,
            ControllersEmulationMode::Quest3Plus => 2,
            ControllersEmulationMode::QuestPro => 3,
            ControllersEmulationMode::Pico4 => 10,
            ControllersEmulationMode::ValveIndex => 20,
            ControllersEmulationMode::ViveWand => 40,
            ControllersEmulationMode::ViveTracker => 41,
            ControllersEmulationMode::Custom { .. } => 500,
        };
        use_separate_hand_trackers = config
            .hand_skeleton
            .as_option()
            .is_some_and(|c| c.steamvr_input_2_0);

        true
    } else {
        false
    };

    let body_tracking_vive_enabled =
        if let Switch::Enabled(config) = &settings.headset.body_tracking {
            matches!(config.sink, BodyTrackingSinkConfig::FakeViveTracker)
        } else {
            false
        };

    // Should be true if using full body tracking
    let body_tracking_has_legs = settings
        .headset
        .body_tracking
        .as_option()
        .and_then(|c| c.sources.body_tracking_fb.as_option().cloned())
        .map(|c| c.full_body)
        .or_else(|| {
            settings.headset.body_tracking.as_option().map(|c| {
                matches!(
                    c.sources.body_tracking_bd.as_option(),
                    Some(BodyTrackingBDConfig::BodyTracking { .. })
                )
            })
        })
        .unwrap_or(false);

    let mut foveation_center_size_x = 0.0;
    let mut foveation_center_size_y = 0.0;
    let mut foveation_center_shift_x = 0.0;
    let mut foveation_center_shift_y = 0.0;
    let mut foveation_edge_ratio_x = 0.0;
    let mut foveation_edge_ratio_y = 0.0;
    let enable_foveated_encoding = if let Switch::Enabled(config) = settings.video.foveated_encoding
    {
        foveation_center_size_x = config.center_size_x;
        foveation_center_size_y = config.center_size_y;
        foveation_center_shift_x = config.center_shift_x;
        foveation_center_shift_y = config.center_shift_y;
        foveation_edge_ratio_x = config.edge_ratio_x;
        foveation_edge_ratio_y = config.edge_ratio_y;

        true
    } else {
        false
    };

    let mut brightness = 0.0;
    let mut contrast = 0.0;
    let mut saturation = 0.0;
    let mut gamma = 0.0;
    let mut sharpening = 0.0;
    let enable_color_correction = if let Switch::Enabled(config) = settings.video.color_correction {
        brightness = config.brightness;
        contrast = config.contrast;
        saturation = config.saturation;
        gamma = config.gamma;
        sharpening = config.sharpening;
        true
    } else {
        false
    };

    let nvenc_overrides = settings.video.encoder_config.nvenc;
    let amf_controls = settings.video.encoder_config.amf;
    let hdr_controls = settings.video.encoder_config.hdr;

    OpenvrConfig {
        tracking_ref_only: settings.headset.tracking_ref_only,
        enable_vive_tracker_proxy: settings.headset.enable_vive_tracker_proxy,
        minimum_idr_interval_ms: settings.connection.minimum_idr_interval_ms,
        adapter_index: settings.video.adapter_index,
        codec: settings.video.preferred_codec as _,
        h264_profile: settings.video.encoder_config.h264_profile as u32,
        rate_control_mode: settings.video.encoder_config.rate_control_mode as u32,
        filler_data: settings.video.encoder_config.filler_data,
        entropy_coding: settings.video.encoder_config.entropy_coding as u32,
        force_hdr_srgb_correction: hdr_controls.force_hdr_srgb_correction,
        clamp_hdr_extended_range: hdr_controls.clamp_hdr_extended_range,
        enable_amf_pre_analysis: amf_controls.enable_pre_analysis,
        enable_vbaq: settings.video.encoder_config.enable_vbaq,
        enable_amf_hmqb: amf_controls.enable_hmqb,
        use_amf_preproc: amf_controls.use_preproc,
        amf_preproc_sigma: amf_controls.preproc_sigma,
        amf_preproc_tor: amf_controls.preproc_tor,
        nvenc_quality_preset: nvenc_overrides.quality_preset as u32,
        encoder_quality_preset: settings.video.encoder_config.quality_preset as u32,
        force_sw_encoding: settings
            .video
            .encoder_config
            .software
            .force_software_encoding,
        sw_thread_count: settings.video.encoder_config.software.thread_count,
        controllers_enabled,
        controller_is_tracker,
        body_tracking_vive_enabled,
        body_tracking_has_legs,
        enable_foveated_encoding,
        foveation_center_size_x,
        foveation_center_size_y,
        foveation_center_shift_x,
        foveation_center_shift_y,
        foveation_edge_ratio_x,
        foveation_edge_ratio_y,
        enable_color_correction,
        brightness,
        contrast,
        saturation,
        gamma,
        sharpening,
        linux_async_compute: settings.extra.patches.linux_async_compute,
        linux_async_reprojection: settings.extra.patches.linux_async_reprojection,
        nvenc_tuning_preset: nvenc_overrides.tuning_preset as u32,
        nvenc_multi_pass: nvenc_overrides.multi_pass as u32,
        nvenc_adaptive_quantization_mode: nvenc_overrides.adaptive_quantization_mode as u32,
        nvenc_low_delay_key_frame_scale: nvenc_overrides.low_delay_key_frame_scale,
        nvenc_refresh_rate: nvenc_overrides.refresh_rate,
        enable_intra_refresh: nvenc_overrides.enable_intra_refresh,
        intra_refresh_period: nvenc_overrides.intra_refresh_period,
        intra_refresh_count: nvenc_overrides.intra_refresh_count,
        max_num_ref_frames: nvenc_overrides.max_num_ref_frames,
        gop_length: nvenc_overrides.gop_length,
        p_frame_strategy: nvenc_overrides.p_frame_strategy,
        nvenc_rate_control_mode: nvenc_overrides.rate_control_mode,
        rc_buffer_size: nvenc_overrides.rc_buffer_size,
        rc_initial_delay: nvenc_overrides.rc_initial_delay,
        rc_max_bitrate: nvenc_overrides.rc_max_bitrate,
        rc_average_bitrate: nvenc_overrides.rc_average_bitrate,
        nvenc_enable_weighted_prediction: nvenc_overrides.enable_weighted_prediction,
        capture_frame_dir: settings.extra.capture.capture_frame_dir,
        amd_bitrate_corruption_fix: settings.video.bitrate.image_corruption_fix,
        use_separate_hand_trackers,
        _controller_profile: controller_profile,
        _server_impl_debug: settings.extra.logging.debug_groups.server_impl,
        _client_impl_debug: settings.extra.logging.debug_groups.client_impl,
        _server_core_debug: settings.extra.logging.debug_groups.server_core,
        _client_core_debug: settings.extra.logging.debug_groups.client_core,
        _connection_debug: settings.extra.logging.debug_groups.connection,
        _sockets_debug: settings.extra.logging.debug_groups.sockets,
        _server_gfx_debug: settings.extra.logging.debug_groups.server_gfx,
        _client_gfx_debug: settings.extra.logging.debug_groups.client_gfx,
        _encoder_debug: settings.extra.logging.debug_groups.encoder,
        _decoder_debug: settings.extra.logging.debug_groups.decoder,
        ..old_config
    }
}

// Alternate connection trials with manual IPs and clients discovered on the local network
pub fn handshake_loop(ctx: Arc<ConnectionContext>, lifecycle_state: Arc<RwLock<LifecycleState>>) {
    dbg_connection!("handshake_loop: Begin");

    {
        let session_manager = SESSION_MANAGER.read();
        let settings = session_manager.settings();

        let mut client_list = String::new();
        for (hostname, info) in session_manager.client_list() {
            client_list.push_str(&format!(
                "\n  {hostname}: state {:?}, trusted {}, manual IPs {:?}, current IP {:?}, display name \"{}\"",
                info.connection_state,
                info.trusted,
                info.manual_ips,
                info.current_ip,
                info.display_name,
            ));
        }

        info!(
            "[HANDSHAKE] loop starting. process id {}, control port {CONTROL_PORT}, stream port {} over {}, discovery {}, auto trust clients {}{}",
            std::process::id(),
            settings.connection.stream_port,
            stream_protocol_desc(&settings.connection.stream_protocol),
            if matches!(settings.connection.client_discovery, Switch::Enabled(_)) {
                "enabled"
            } else {
                "DISABLED"
            },
            if let Switch::Enabled(config) = &settings.connection.client_discovery {
                config.auto_trust_clients
            } else {
                false
            },
            if client_list.is_empty() {
                "\n  no configured clients".to_owned()
            } else {
                format!("configured clients:{client_list}")
            },
        );
    }

    let mut welcome_socket = match WelcomeSocket::new() {
        Ok(socket) => socket,
        Err(e) => {
            error!("Failed to create discovery socket: {e:?}");
            return;
        }
    };

    let mut wired_connection = None;

    while *lifecycle_state.read() != LifecycleState::ShuttingDown {
        let iteration = HANDSHAKE_LOOP_ITERATION.fetch_add(1, AtomicOrdering::Relaxed);

        info!(
            "[HANDSHAKE] iteration #{iteration}: lifecycle state {:?}",
            *lifecycle_state.read(),
        );

        // The client only waits 500ms for the stream config after accepting the connection, while
        // enumerating audio devices (virtual audio cables especially) can take longer than that.
        // Computing the value while idle means the handshake can be served immediately.
        {
            let settings = SESSION_MANAGER.read().settings().clone();
            let start = Instant::now();

            match warm_game_audio_sample_rate(&settings) {
                Ok(()) => {
                    if start.elapsed() > Duration::from_millis(50) {
                        info!(
                            "[AUDIO] precomputed the game audio sample rate in {:?} while idle. This delay would otherwise land between the client connecting and receiving the stream config, which the client only tolerates for 500ms",
                            start.elapsed(),
                        );
                    }
                }
                Err(e) => warn!("[AUDIO] could not precompute the game audio sample rate: {e}"),
            }
        }

        dbg_connection!("handshake_loop: Try connect to wired device");

        let mut wired_client_ips = HashMap::new();
        if SESSION_MANAGER
            .read()
            .client_list()
            .iter()
            .any(|(hostname, info)| {
                info.connection_state == ConnectionState::Disconnected
                    && hostname.as_str() == WIRED_CLIENT_HOSTNAME
            })
        {
            // Make sure the wired connection is created once and kept alive
            let wired_connection = if let Some(connection) = &wired_connection {
                connection
            } else {
                let connection = match WiredConnection::new(
                    FILESYSTEM_LAYOUT.get().unwrap(),
                    |downloaded, maybe_total| {
                        if let Some(total) = maybe_total {
                            alvr_events::send_event(EventType::Adb(AdbEvent {
                                download_progress: downloaded as f32 / total as f32,
                            }));
                        };
                    },
                ) {
                    Ok(connection) => connection,
                    Err(e) => {
                        error!("{e:?}");
                        thread::sleep(RETRY_CONNECT_MIN_INTERVAL);
                        continue;
                    }
                };

                wired_connection = Some(connection);

                wired_connection.as_ref().unwrap()
            };

            let stream_port;
            let client_type;
            let client_autolaunch;
            {
                let session_manager_lock = SESSION_MANAGER.read();
                let connection = &session_manager_lock.settings().connection;
                stream_port = connection.stream_port;
                client_type = connection.wired_client_type.clone();
                client_autolaunch = connection.wired_client_autolaunch;
            }

            let status = match wired_connection.setup(
                CONTROL_PORT,
                stream_port,
                &client_type,
                client_autolaunch,
            ) {
                Ok(status) => status,
                Err(e) => {
                    error!("{e:?}");
                    thread::sleep(RETRY_CONNECT_MIN_INTERVAL);
                    continue;
                }
            };

            #[cfg_attr(not(debug_assertions), expect(unused_variables))]
            if let WiredConnectionStatus::NotReady(s) = status {
                info!("[HANDSHAKE] iteration #{iteration}: wired ADB client not ready: {s}");
                dbg_connection!("handshake_loop: Wired connection not ready: {s}");
                thread::sleep(RETRY_CONNECT_MIN_INTERVAL);
                continue;
            }

            let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
            wired_client_ips.insert(client_ip, WIRED_CLIENT_HOSTNAME.to_owned());
        }

        if !wired_client_ips.is_empty() {
            let start = Instant::now();
            let res = try_connect(
                Arc::clone(&ctx),
                Arc::clone(&lifecycle_state),
                wired_client_ips.clone(),
            );

            match &res {
                Ok(()) => {
                    info!(
                        "[HANDSHAKE] iteration #{iteration}: wired attempt to {wired_client_ips:?} accepted after {:?}",
                        start.elapsed()
                    );

                    thread::sleep(RETRY_CONNECT_MIN_INTERVAL);
                    continue;
                }
                Err(e) => info!(
                    "[HANDSHAKE] iteration #{iteration}: wired attempt to {wired_client_ips:?} failed after {:?}: {e}",
                    start.elapsed()
                ),
            }
        }

        dbg_connection!("handshake_loop: Try connect to manual IPs");

        let available_manual_client_ips = {
            let mut manual_client_ips = HashMap::new();
            for (hostname, connection_info) in
                SESSION_MANAGER
                    .read()
                    .client_list()
                    .iter()
                    .filter(|(hostname, info)| {
                        info.connection_state == ConnectionState::Disconnected
                            && hostname.as_str() != WIRED_CLIENT_HOSTNAME
                    })
            {
                for ip in &connection_info.manual_ips {
                    manual_client_ips.insert(*ip, hostname.clone());
                }
            }
            manual_client_ips
        };

        if !available_manual_client_ips.is_empty() {
            let start = Instant::now();
            let res = try_connect(
                Arc::clone(&ctx),
                Arc::clone(&lifecycle_state),
                available_manual_client_ips.clone(),
            );

            match &res {
                Ok(()) => {
                    info!(
                        "[HANDSHAKE] iteration #{iteration}: manual IP attempt to {available_manual_client_ips:?} accepted after {:?}",
                        start.elapsed()
                    );

                    thread::sleep(RETRY_CONNECT_MIN_INTERVAL);
                    continue;
                }
                Err(e) => info!(
                    "[HANDSHAKE] iteration #{iteration}: manual IP attempt to {available_manual_client_ips:?} failed after {:?}: {e}",
                    start.elapsed()
                ),
            }
        }

        let discovery_config = SESSION_MANAGER
            .read()
            .settings()
            .connection
            .client_discovery
            .clone();
        if let Switch::Enabled(config) = discovery_config {
            dbg_connection!("handshake_loop: Discovering clients");

            let clients = match welcome_socket.recv_all() {
                Ok(clients) => clients,
                Err(e) => {
                    warn!("UDP handshake listening error: {e:?}");

                    thread::sleep(RETRY_CONNECT_MIN_INTERVAL);
                    continue;
                }
            };

            if clients.is_empty() {
                info!(
                    "[HANDSHAKE] iteration #{iteration}: no client announced itself (no broadcast packet and no mDNS announcement)"
                );

                thread::sleep(RETRY_CONNECT_MIN_INTERVAL);
                continue;
            }

            info!("[HANDSHAKE] iteration #{iteration}: discovered {clients:?}");

            for (client_hostname, client_ip) in clients {
                let trusted = {
                    let mut session_manager = SESSION_MANAGER.write();

                    session_manager.update_client_list(
                        client_hostname.clone(),
                        ClientListAction::AddIfMissing {
                            trusted: false,
                            manual_ips: vec![],
                        },
                    );

                    if config.auto_trust_clients {
                        session_manager
                            .update_client_list(client_hostname.clone(), ClientListAction::Trust);
                    }

                    session_manager
                        .client_list()
                        .get(&client_hostname)
                        .is_some_and(|c| c.trusted)
                };

                // do not attempt connection if the client is already connected
                if trusted
                    && SESSION_MANAGER
                        .read()
                        .client_list()
                        .get(&client_hostname)
                        .is_some_and(|c| c.connection_state == ConnectionState::Disconnected)
                {
                    let start = Instant::now();
                    let res = try_connect(
                        Arc::clone(&ctx),
                        Arc::clone(&lifecycle_state),
                        [(client_ip, client_hostname.clone())].into_iter().collect(),
                    );

                    match &res {
                        Ok(()) => info!(
                            "[HANDSHAKE] iteration #{iteration}: control socket for {client_hostname} ({client_ip}) opened after {:?}, see the pipeline logs for the handshake result",
                            start.elapsed()
                        ),
                        Err(e) => error!("Could not initiate connection for {client_hostname}: {e}"),
                    }
                } else {
                    info!(
                        "[HANDSHAKE] iteration #{iteration}: not connecting to {client_hostname} ({client_ip}): trusted {}, connection state {}",
                        trusted,
                        SESSION_MANAGER
                            .read()
                            .client_list()
                            .get(&client_hostname)
                            .map_or_else(
                                || "<not in the client list>".to_owned(),
                                |c| format!("{:?}", c.connection_state)
                            ),
                    );
                }

                thread::sleep(RETRY_CONNECT_MIN_INTERVAL);
            }
        } else {
            thread::sleep(RETRY_CONNECT_MIN_INTERVAL);
        }
    }

    alvr_common::dbg_connection!("handshake_loop: Joining connection threads");

    // At this point, LIFECYCLE_STATE == ShuttingDown, so all threads are already terminating
    for thread in ctx.connection_threads.lock().drain(..) {
        thread.join().ok();
    }

    alvr_common::dbg_connection!("handshake_loop: End");
}

fn try_connect(
    ctx: Arc<ConnectionContext>,
    lifecycle_state: Arc<RwLock<LifecycleState>>,
    mut client_ips: HashMap<IpAddr, String>,
) -> ConResult {
    let attempt = CONNECTION_ATTEMPT_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let start = Instant::now();

    info!("[HANDSHAKE] attempt #{attempt}: opening a control socket to {client_ips:?}");

    dbg_connection!("try_connect: Finding client and creating control socket");

    let (proto_socket, client_ip) = match ProtoControlSocket::connect_to(
        Duration::from_secs(1),
        PeerType::AnyClient(client_ips.keys().cloned().collect()),
    ) {
        Ok(pair) => pair,
        Err(e) => {
            info!(
                "[HANDSHAKE] attempt #{attempt}: could not open a control socket to {client_ips:?} after {:?}: {e}",
                start.elapsed()
            );

            return Err(e);
        }
    };

    let Some(client_hostname) = client_ips.remove(&client_ip) else {
        con_bail!("unreachable");
    };

    info!(
        "[HANDSHAKE] attempt #{attempt}: control socket with {client_hostname} ({client_ip}) established in {:?}, spawning the connection thread",
        start.elapsed()
    );

    dbg_connection!("try_connect: Pushing new client connection thread");

    ctx.connection_threads.lock().push(thread::spawn({
        let ctx = Arc::clone(&ctx);
        move || {
            info!("[HANDSHAKE] attempt #{attempt}: connection thread for {client_hostname} ({client_ip}) started");

            match connection_pipeline(
                Arc::clone(&ctx),
                lifecycle_state,
                proto_socket,
                client_hostname.clone(),
                client_ip,
            ) {
                Ok(()) => info!(
                    "[HANDSHAKE] attempt #{attempt}: connection pipeline for {client_hostname} ({client_ip}) returned without a handshake error"
                ),
                Err(e) => error!("Handshake error for {client_hostname}: {e}"),
            }

            let mut clients_to_be_removed = ctx.clients_to_be_removed.lock();

            let (action, action_desc) = if clients_to_be_removed.contains(&client_hostname) {
                clients_to_be_removed.remove(&client_hostname);

                (
                    ClientListAction::RemoveEntry,
                    "removing the client entry",
                )
            } else {
                (
                    ClientListAction::SetConnectionState(ConnectionState::Disconnected),
                    "setting the client state back to Disconnected",
                )
            };
            SESSION_MANAGER
                .write()
                .update_client_list(client_hostname.clone(), action);

            let resulting_state = SESSION_MANAGER
                .read()
                .client_list()
                .get(&client_hostname)
                .map_or_else(
                    || "<not in the client list>".to_owned(),
                    |c| format!("{:?}", c.connection_state),
                );

            info!(
                "[HANDSHAKE] attempt #{attempt}: {action_desc} for {client_hostname} (new state {resulting_state})"
            );
        }
    }));

    Ok(())
}

fn connection_pipeline(
    ctx: Arc<ConnectionContext>,
    lifecycle_state: Arc<RwLock<LifecycleState>>,
    mut proto_socket: ProtoControlSocket,
    client_hostname: String,
    client_ip: IpAddr,
) -> ConResult {
    dbg_connection!("connection_pipeline: Begin");

    let pipeline_start = Instant::now();

    info!(
        "[PIPELINE] {client_hostname} ({client_ip}): handshake started, taking the session lock (this blocks all other connection attempts)"
    );

    // This session lock will make sure settings and client list cannot be changed while connecting
    // to thos client, no other client can connect until handshake is finished. It will then be
    // temporarily relocked while shutting down the threads.
    let lock_start = Instant::now();
    let mut session_manager_lock = SESSION_MANAGER.write();

    info!(
        "[PIPELINE] {client_hostname}: session lock acquired in {:?} ({:?} since the pipeline started)",
        lock_start.elapsed(),
        pipeline_start.elapsed(),
    );

    dbg_connection!("connection_pipeline: Setting client state in session");
    session_manager_lock.update_client_list(
        client_hostname.clone(),
        ClientListAction::SetConnectionState(ConnectionState::Connecting),
    );
    session_manager_lock.update_client_list(
        client_hostname.clone(),
        ClientListAction::UpdateCurrentIp(Some(client_ip)),
    );

    let disconnect_notif = Arc::new(Condvar::new());

    dbg_connection!("connection_pipeline: Getting client status packet");

    let recv_start = Instant::now();

    info!(
        "[PIPELINE] {client_hostname}: waiting up to {HANDSHAKE_ACTION_TIMEOUT:?} for the client connection packet (see the [CTRL-RX] logs above for the raw socket result)"
    );

    let connection_result = match proto_socket.recv(HANDSHAKE_ACTION_TIMEOUT) {
        Ok(result) => {
            info!(
                "[PIPELINE] {client_hostname}: received the client connection packet in {:?}; the client is {}",
                recv_start.elapsed(),
                if proto_socket.peer_is_alive() {
                    "still connected"
                } else {
                    "ALREADY GONE"
                },
            );

            result
        }
        Err(ConnectionError::TryAgain(e)) => {
            info!(
                "[PIPELINE] {client_hostname}: no client connection packet within {:?}; abandoning this attempt (the client is not answering on the control port). Detail: {e}",
                recv_start.elapsed(),
            );

            debug!("Failed to recive client connection packet. This is normal for USB connection.\n{e}");

            return Ok(());
        }
        Err(e) => {
            info!(
                "[PIPELINE] {client_hostname}: FAILED to receive the client connection packet after {:?}: {e}",
                recv_start.elapsed(),
            );

            return Err(e);
        }
    };

    let maybe_streaming_caps = if let ClientConnectionResult::ConnectionAccepted {
        client_protocol_id,
        display_name,
        streaming_capabilities,
        ..
    } = connection_result
    {
        info!(
            "[PIPELINE] {client_hostname}: client accepted the connection. display name \"{display_name}\", protocol id {client_protocol_id}, streaming capabilities {}",
            if streaming_capabilities.is_some() {
                "provided"
            } else {
                "MISSING"
            },
        );

        session_manager_lock.update_client_list(
            client_hostname.clone(),
            ClientListAction::SetDisplayName(display_name),
        );

        if client_protocol_id != alvr_common::protocol_id_u64() {
            info!(
                "[PIPELINE] {client_hostname}: protocol mismatch, abandoning the handshake after {:?}",
                pipeline_start.elapsed(),
            );

            warn!(
                "Trusted client is incompatible! Expected protocol ID: {}, found: {}",
                alvr_common::protocol_id_u64(),
                client_protocol_id,
            );

            return Ok(());
        }

        streaming_capabilities
    } else {
        info!("[PIPELINE] {client_hostname}: client is in standby, retrying");

        debug!("Found client in standby. Retrying");
        return Ok(());
    };

    let streaming_caps = if let Some(streaming_caps) = maybe_streaming_caps {
        match alvr_packets::decode_video_streaming_capabilities(&streaming_caps).to_con() {
            Ok(streaming_caps) => {
                info!(
                    "[PIPELINE] {client_hostname}: decoded the client streaming capabilities in {:?} (default view resolution {:?}, refresh rates {:?}, H264 high profile {}, 10 bit {}, AV1 {}, multimodal {})",
                    pipeline_start.elapsed(),
                    streaming_caps.default_view_resolution,
                    streaming_caps.supported_refresh_rates,
                    streaming_caps.encoder_high_profile,
                    streaming_caps.encoder_10_bits,
                    streaming_caps.encoder_av1,
                    streaming_caps.multimodal_protocol,
                );

                streaming_caps
            }
            Err(e) => {
                info!(
                    "[PIPELINE] {client_hostname}: FAILED to decode the client streaming capabilities after {:?}: {e}",
                    pipeline_start.elapsed(),
                );

                return Err(e);
            }
        }
    } else {
        info!("[PIPELINE] {client_hostname}: client provided no streaming capabilities, abandoning the handshake");

        con_bail!("Only streaming clients are supported for now");
    };

    dbg_connection!("connection_pipeline: setting up negotiated streaming config");

    let initial_settings = session_manager_lock.settings().clone();

    fn get_view_res(config: FrameSize, default_res: UVec2) -> UVec2 {
        let res = match config {
            FrameSize::Scale(scale) => default_res.as_vec2() * scale,
            FrameSize::Absolute { width, height } => {
                let width = width as f32;
                Vec2::new(
                    width,
                    height.map_or_else(
                        || {
                            let default_res = default_res.as_vec2();
                            width * default_res.y / default_res.x
                        },
                        |h| h as f32,
                    ),
                )
            }
        };

        UVec2::new(align32(res.x), align32(res.y))
    }

    let stream_view_resolution = get_view_res(
        initial_settings.video.transcoding_view_resolution.clone(),
        streaming_caps.default_view_resolution,
    );

    let target_view_resolution = get_view_res(
        initial_settings
            .video
            .emulated_headset_view_resolution
            .clone(),
        streaming_caps.default_view_resolution,
    );

    let fps = {
        let mut best_match = 0_f32;
        let mut min_diff = f32::MAX;
        for rate in &streaming_caps.supported_refresh_rates {
            let diff = (*rate - initial_settings.video.preferred_fps).abs();
            if diff < min_diff {
                best_match = *rate;
                min_diff = diff;
            }
        }
        best_match
    };

    if !streaming_caps
        .supported_refresh_rates
        .contains(&initial_settings.video.preferred_fps)
    {
        warn!("Chosen refresh rate not supported. Using {fps}Hz");
    }

    let enable_foveated_encoding =
        if let Switch::Enabled(config) = &initial_settings.video.foveated_encoding {
            let enable = streaming_caps.supports_foveated_encoding || config.force_enable;

            if !enable {
                warn!("Foveated encoding is not supported by the client.");
            }

            enable
        } else {
            false
        };

    let encoder_profile = if initial_settings.video.encoder_config.h264_profile == H264Profile::High
    {
        let profile = if streaming_caps.encoder_high_profile {
            H264Profile::High
        } else {
            H264Profile::Main
        };

        if profile != H264Profile::High {
            warn!("High profile encoding is not supported by the client.");
        }

        profile
    } else {
        initial_settings.video.encoder_config.h264_profile
    };

    let mut enable_10_bits_encoding = if initial_settings
        .video
        .encoder_config
        .server_overrides_use_10bit
    {
        initial_settings.video.encoder_config.use_10bit
    } else {
        streaming_caps.prefer_10bit
    };

    if enable_10_bits_encoding && !streaming_caps.encoder_10_bits {
        warn!("10 bits encoding is not supported by the client.");
        enable_10_bits_encoding = false
    }

    let use_full_range = if initial_settings
        .video
        .encoder_config
        .server_overrides_use_full_range
    {
        initial_settings.video.encoder_config.use_full_range
    } else {
        streaming_caps.prefer_full_range
    };

    let enable_hdr = if initial_settings
        .video
        .encoder_config
        .hdr
        .server_overrides_enable_hdr
    {
        initial_settings.video.encoder_config.hdr.enable_hdr
    } else {
        streaming_caps.prefer_hdr
    };

    let encoding_gamma = if initial_settings
        .video
        .encoder_config
        .server_overrides_encoding_gamma
    {
        initial_settings.video.encoder_config.encoding_gamma
    } else {
        streaming_caps.preferred_encoding_gamma
    };

    let codec = if initial_settings.video.preferred_codec == CodecType::AV1 {
        let codec = if streaming_caps.encoder_av1 {
            CodecType::AV1
        } else {
            CodecType::Hevc
        };

        if codec != CodecType::AV1 {
            warn!("AV1 encoding is not supported by the client.");
        }

        codec
    } else {
        initial_settings.video.preferred_codec
    };

    let game_audio_sample_rate = {
        let start = Instant::now();
        let sample_rate = cached_game_audio_sample_rate(&initial_settings)?;
        info!(
            "[PIPELINE] {client_hostname}: game audio sample rate {sample_rate} resolved in {:?}",
            start.elapsed(),
        );

        sample_rate
    };

    let wired = client_ip.is_loopback();

    dbg_connection!("connection_pipeline: send streaming config");

    if !proto_socket.peer_is_alive() {
        info!(
            "[PIPELINE] {client_hostname}: THE CLIENT HAS ALREADY CLOSED THE CONTROL CONNECTION, {:?} after it accepted. The client gives up 500ms after accepting if the stream config has not arrived yet",
            pipeline_start.elapsed(),
        );
    } else {
        info!(
            "[PIPELINE] {client_hostname}: the client is still connected {:?} after it accepted, sending the streaming configuration now",
            pipeline_start.elapsed(),
        );
    }

    let stream_config_packet = alvr_packets::encode_stream_config(
        session_manager_lock.session(),
        &NegotiatedStreamingConfig {
            view_resolution: stream_view_resolution,
            refresh_rate_hint: fps,
            game_audio_sample_rate,
            enable_foveated_encoding,
            use_multimodal_protocol: streaming_caps.multimodal_protocol,
            use_full_range,
            encoding_gamma,
            enable_hdr,
            wired,
        },
    )
    .to_con()?;

    info!(
        "[PIPELINE] {client_hostname}: sending the streaming configuration after {:?} (view {},{} @ {}Hz, game audio sample rate {}, foveated {}, wired {})",
        pipeline_start.elapsed(),
        stream_view_resolution.x,
        stream_view_resolution.y,
        fps,
        game_audio_sample_rate,
        enable_foveated_encoding,
        wired,
    );

    match proto_socket.send(&stream_config_packet).to_con() {
        Ok(()) => info!(
            "[PIPELINE] {client_hostname}: streaming configuration sent after {:?}",
            pipeline_start.elapsed()
        ),
        Err(e) => {
            info!(
                "[PIPELINE] {client_hostname}: FAILED to send the streaming configuration after {:?}: {e}",
                pipeline_start.elapsed()
            );

            return Err(e);
        }
    }

    let (mut control_sender, mut control_receiver) =
        match proto_socket.split(STREAMING_RECV_TIMEOUT).to_con() {
            Ok(pair) => pair,
            Err(e) => {
                info!(
                "[PIPELINE] {client_hostname}: FAILED to split the control socket after {:?}: {e}",
                pipeline_start.elapsed()
            );

                return Err(e);
            }
        };

    info!("[PIPELINE] {client_hostname}: control socket split into sender and receiver");

    let mut new_openvr_config = contruct_openvr_config(session_manager_lock.session());
    new_openvr_config.eye_resolution_width = stream_view_resolution.x;
    new_openvr_config.eye_resolution_height = stream_view_resolution.y;
    new_openvr_config.target_eye_resolution_width = target_view_resolution.x;
    new_openvr_config.target_eye_resolution_height = target_view_resolution.y;
    new_openvr_config.refresh_rate = fps as _;
    new_openvr_config.enable_foveated_encoding = enable_foveated_encoding;
    new_openvr_config.h264_profile = encoder_profile as _;
    new_openvr_config.use_10bit_encoder = enable_10_bits_encoding;
    new_openvr_config.use_full_range_encoding = use_full_range;
    new_openvr_config.enable_hdr = enable_hdr;
    new_openvr_config.encoding_gamma = encoding_gamma;
    new_openvr_config.codec = codec as _;

    if session_manager_lock.session().openvr_config != new_openvr_config {
        session_manager_lock.session_mut().openvr_config = new_openvr_config;

        control_sender.send(&ServerControlPacket::Restarting).ok();

        crate::notify_restart_driver();
    }

    dbg_connection!("connection_pipeline: Send StartStream packet");

    info!("[PIPELINE] {client_hostname}: sending StartStream");

    match control_sender
        .send(&ServerControlPacket::StartStream)
        .to_con()
    {
        Ok(()) => info!("[PIPELINE] {client_hostname}: StartStream sent"),
        Err(e) => {
            info!(
                "[PIPELINE] {client_hostname}: FAILED to send StartStream after {:?}: {e}",
                pipeline_start.elapsed()
            );

            return Err(e);
        }
    }

    let ack_start = Instant::now();

    info!(
        "[PIPELINE] {client_hostname}: waiting up to {HANDSHAKE_ACTION_TIMEOUT:?} for the StreamReady acknowledgement"
    );

    let signal = match control_receiver.recv_within(HANDSHAKE_ACTION_TIMEOUT) {
        Ok(signal) => {
            info!(
                "[PIPELINE] {client_hostname}: got an acknowledgement in {:?}: {}",
                ack_start.elapsed(),
                client_control_packet_desc(&signal),
            );

            signal
        }
        Err(e) => {
            info!(
                "[PIPELINE] {client_hostname}: FAILED to get the StreamReady acknowledgement after {:?}: {e}",
                ack_start.elapsed()
            );

            return Err(e);
        }
    };

    if !matches!(signal, ClientControlPacket::StreamReady) {
        info!(
            "[PIPELINE] {client_hostname}: unexpected acknowledgement waiting for the stream ack after {:?}",
            pipeline_start.elapsed()
        );

        con_bail!("Got unexpected packet waiting for stream ack");
    }
    dbg_connection!("connection_pipeline: Got StreamReady packet");

    *ctx.statistics_manager.write() = Some(StatisticsManager::new(
        initial_settings.connection.statistics_history_size,
        Duration::from_secs_f32(1.0 / fps),
        if let Switch::Enabled(config) = &initial_settings.headset.controllers {
            config.steamvr_pipeline_frames
        } else {
            0.0
        },
    ));

    *ctx.bitrate_manager.lock() =
        BitrateManager::new(initial_settings.video.bitrate.history_size, fps);

    let stream_protocol = if wired {
        SocketProtocol::Tcp
    } else {
        initial_settings.connection.stream_protocol
    };

    dbg_connection!("connection_pipeline: StreamSocket connect_to_client");

    let stream_socket_start = Instant::now();

    info!(
        "[PIPELINE] {client_hostname}: opening the stream socket to {client_ip}:{} over {} (wired {wired}) after {:?}",
        initial_settings.connection.stream_port,
        stream_protocol_desc(&stream_protocol),
        pipeline_start.elapsed(),
    );

    let mut stream_socket = match StreamSocketBuilder::connect_to_client(
        HANDSHAKE_ACTION_TIMEOUT,
        client_ip,
        initial_settings.connection.stream_port,
        stream_protocol,
        initial_settings.connection.dscp,
        initial_settings.connection.server_send_buffer_bytes,
        initial_settings.connection.server_recv_buffer_bytes,
        initial_settings.connection.packet_size as _,
    ) {
        Ok(stream_socket) => {
            info!(
                "[PIPELINE] {client_hostname}: stream socket ready in {:?}",
                stream_socket_start.elapsed()
            );

            stream_socket
        }
        Err(e) => {
            info!(
                "[PIPELINE] {client_hostname}: FAILED to open the stream socket after {:?}: {e}",
                stream_socket_start.elapsed()
            );

            return Err(e);
        }
    };

    let mut video_sender = stream_socket.request_stream(VIDEO);
    let game_audio_sender: alvr_sockets::StreamSender<()> = stream_socket.request_stream(AUDIO);
    let mut microphone_receiver: alvr_sockets::StreamReceiver<()> =
        stream_socket.subscribe_to_stream(AUDIO, MAX_UNREAD_PACKETS);
    let tracking_receiver =
        stream_socket.subscribe_to_stream::<Tracking>(TRACKING, MAX_UNREAD_PACKETS);
    let haptics_sender = stream_socket.request_stream(HAPTICS);
    let mut statics_receiver =
        stream_socket.subscribe_to_stream::<ClientStatistics>(STATISTICS, MAX_UNREAD_PACKETS);

    let (video_channel_sender, video_channel_receiver) =
        std::sync::mpsc::sync_channel(initial_settings.connection.max_queued_server_video_frames);
    *ctx.video_channel_sender.lock() = Some(video_channel_sender);
    *ctx.haptics_sender.lock() = Some(haptics_sender);

    let video_send_thread = thread::spawn({
        let client_hostname = client_hostname.clone();
        move || {
            while is_streaming(&client_hostname) {
                let VideoPacket { header, payload } =
                    match video_channel_receiver.recv_timeout(STREAMING_RECV_TIMEOUT) {
                        Ok(packet) => packet,
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(RecvTimeoutError::Disconnected) => return,
                    };

                let mut buffer = video_sender.get_buffer(&header).unwrap();
                // todo: make encoder write to socket buffers directly to avoid copy
                buffer
                    .get_range_mut(0, payload.len())
                    .copy_from_slice(&payload);
                video_sender.send(buffer).ok();
            }
        }
    });

    #[cfg_attr(target_os = "linux", allow(unused_variables))]
    let game_audio_thread = if let Switch::Enabled(config) =
        initial_settings.audio.game_audio.clone()
    {
        #[cfg(windows)]
        let ctx = Arc::clone(&ctx);

        let client_hostname = client_hostname.clone();
        thread::spawn(move || {
            while is_streaming(&client_hostname) {
                #[cfg(target_os = "linux")]
                if let Err(e) = alvr_audio::linux::record_audio_blocking_pipewire(
                    Arc::new({
                        let client_hostname = client_hostname.clone();
                        move || is_streaming(&client_hostname)
                    }),
                    game_audio_sender.clone(),
                    2,
                    game_audio_sample_rate,
                ) {
                    error!("Audio record error: {e:?}");
                }

                #[cfg(not(target_os = "linux"))]
                {
                    let device = match alvr_audio::AudioDevice::new_output(config.device.as_ref()) {
                        Ok(data) => data,
                        Err(e) => {
                            warn!("New audio device failed: {e:?}");
                            thread::sleep(RETRY_CONNECT_MIN_INTERVAL);
                            continue;
                        }
                    };

                    #[cfg(windows)]
                    if let Ok(id) = alvr_audio::get_windows_device_id(&device) {
                        let prop = alvr_session::OpenvrProperty {
                            key: alvr_session::OpenvrPropKey::AudioDefaultPlaybackDeviceIdString,
                            value: id,
                        };
                        ctx.events_sender
                            .send(ServerCoreEvent::SetOpenvrProperty {
                                device_id: *alvr_common::HEAD_ID,
                                prop,
                            })
                            .ok();
                    } else {
                        continue;
                    };

                    if let Err(e) = alvr_audio::record_audio_blocking(
                        Arc::new({
                            let client_hostname = client_hostname.clone();
                            move || is_streaming(&client_hostname)
                        }),
                        game_audio_sender.clone(),
                        &device,
                        2,
                        config.mute_when_streaming,
                    ) {
                        error!("Audio record error: {e:?}");
                    }

                    #[cfg(windows)]
                    if let Ok(id) = alvr_audio::AudioDevice::new_output(None)
                        .and_then(|d| alvr_audio::get_windows_device_id(&d))
                    {
                        let prop = alvr_session::OpenvrProperty {
                            key: alvr_session::OpenvrPropKey::AudioDefaultPlaybackDeviceIdString,
                            value: id,
                        };
                        ctx.events_sender
                            .send(ServerCoreEvent::SetOpenvrProperty {
                                device_id: *alvr_common::HEAD_ID,
                                prop,
                            })
                            .ok();
                    }
                }
            }
        })
    } else {
        thread::spawn(|| ())
    };

    let microphone_thread =
        if let Switch::Enabled(config) = initial_settings.audio.microphone.clone() {
            #[cfg(not(target_os = "linux"))]
            #[allow(unused_variables)]
            let (sink, source) =
                alvr_audio::AudioDevice::new_virtual_microphone_pair(config.devices).to_con()?;

            #[cfg(windows)]
            if let Ok(id) = alvr_audio::get_windows_device_id(&source) {
                ctx.events_sender
                    .send(ServerCoreEvent::SetOpenvrProperty {
                        device_id: *alvr_common::HEAD_ID,
                        prop: alvr_session::OpenvrProperty {
                            key: alvr_session::OpenvrPropKey::AudioDefaultRecordingDeviceIdString,
                            value: id,
                        },
                    })
                    .ok();
            }

            let client_hostname = client_hostname.clone();
            thread::spawn(move || {
                #[cfg(not(target_os = "linux"))]
                alvr_common::show_err(alvr_audio::play_audio_loop(
                    {
                        let client_hostname = client_hostname.clone();
                        move || is_streaming(&client_hostname)
                    },
                    &sink,
                    1,
                    streaming_caps.microphone_sample_rate,
                    config.buffering,
                    &mut microphone_receiver,
                ));
                #[cfg(target_os = "linux")]
                alvr_common::show_err(alvr_audio::linux::play_microphone_loop_pipewire(
                    {
                        let client_hostname = client_hostname.clone();
                        move || is_streaming(&client_hostname)
                    },
                    1,
                    streaming_caps.microphone_sample_rate,
                    config.buffering,
                    &mut microphone_receiver,
                ));
            })
        } else {
            thread::spawn(|| ())
        };

    *ctx.tracking_manager.write() =
        TrackingManager::new(initial_settings.connection.statistics_history_size);
    let hand_gesture_manager = Arc::new(Mutex::new(HandGestureManager::new()));

    let tracking_receive_thread = thread::spawn({
        let ctx = Arc::clone(&ctx);
        let hand_gesture_manager = Arc::clone(&hand_gesture_manager);
        let initial_settings = initial_settings.clone();
        let client_hostname = client_hostname.clone();
        move || {
            tracking::tracking_loop(
                &ctx,
                initial_settings,
                streaming_caps.multimodal_protocol,
                hand_gesture_manager,
                tracking_receiver,
                || is_streaming(&client_hostname),
            );
        }
    });

    let statistics_thread = thread::spawn({
        let ctx = Arc::clone(&ctx);
        let client_hostname = client_hostname.clone();
        move || {
            while is_streaming(&client_hostname) {
                let data = match statics_receiver.recv(STREAMING_RECV_TIMEOUT) {
                    Ok(stats) => stats,
                    Err(ConnectionError::TryAgain(_)) => continue,
                    Err(ConnectionError::Other(_)) => return,
                };
                let Ok(client_stats) = data.get_header() else {
                    return;
                };

                if let Some(stats) = &mut *ctx.statistics_manager.write() {
                    let timestamp = client_stats.target_timestamp;
                    let decoder_latency = client_stats.video_decode;
                    let (network_latency, game_latency) = stats.report_statistics(client_stats);

                    ctx.events_sender
                        .send(ServerCoreEvent::GameRenderLatencyFeedback(game_latency))
                        .ok();

                    let session_manager_lock = SESSION_MANAGER.read();
                    ctx.bitrate_manager.lock().report_frame_latencies(
                        &session_manager_lock.settings().video.bitrate.mode,
                        timestamp,
                        network_latency,
                        decoder_latency,
                    );
                }
            }
        }
    });

    let control_sender = Arc::new(Mutex::new(control_sender));

    let real_time_update_thread = thread::spawn({
        let control_sender = Arc::clone(&control_sender);
        let client_hostname = client_hostname.clone();
        move || {
            while is_streaming(&client_hostname) {
                let config = {
                    let session_manager_lock = SESSION_MANAGER.read();
                    let settings = session_manager_lock.settings();

                    RealTimeConfig::from_settings(settings)
                };

                if let Ok(config) = config.encode() {
                    control_sender.lock().send(&config).ok();
                }

                thread::sleep(REAL_TIME_UPDATE_INTERVAL);
            }
        }
    });

    let keepalive_thread = thread::spawn({
        let control_sender = Arc::clone(&control_sender);
        let disconnect_notif = Arc::clone(&disconnect_notif);
        let client_hostname = client_hostname.clone();
        move || {
            while is_streaming(&client_hostname) {
                if let Err(e) = control_sender.lock().send(&ServerControlPacket::KeepAlive) {
                    info!("Client disconnected. Cause: {e:?}");

                    disconnect_notif.notify_one();

                    return;
                }

                thread::sleep(KEEPALIVE_INTERVAL);
            }
        }
    });

    let control_receive_thread = thread::spawn({
        let ctx = Arc::clone(&ctx);

        let controllers_config = session_manager_lock
            .settings()
            .headset
            .controllers
            .as_option();
        let mut controller_button_mapping_manager = controllers_config.map(|config| {
            if let Some(mappings) = &config.button_mappings {
                ButtonMappingManager::new_manual(mappings)
            } else {
                ButtonMappingManager::new_automatic(
                    &CONTROLLER_PROFILE_INFO
                        .get(&alvr_common::hash_string(QUEST_CONTROLLER_PROFILE_PATH))
                        .unwrap()
                        .button_set,
                    &config.emulation_mode,
                    &config.button_mapping_config,
                )
            }
        });
        let controllers_emulation_mode =
            controllers_config.map(|config| config.emulation_mode.clone());

        let disconnect_notif = Arc::clone(&disconnect_notif);
        let control_sender = Arc::clone(&control_sender);
        let client_hostname = client_hostname.clone();
        move || {
            let mut disconnection_deadline = Instant::now() + KEEPALIVE_TIMEOUT;
            while is_streaming(&client_hostname) {
                let packet = match control_receiver.recv(STREAMING_RECV_TIMEOUT) {
                    Ok(packet) => packet,
                    Err(ConnectionError::TryAgain(_)) => {
                        if Instant::now() > disconnection_deadline {
                            info!("Client disconnected. Timeout");
                            break;
                        } else {
                            continue;
                        }
                    }
                    Err(e) => {
                        info!("Client disconnected. Cause: {e}");
                        break;
                    }
                };

                match packet {
                    ClientControlPacket::PlayspaceSync(packet) => {
                        if !initial_settings.headset.tracking_ref_only {
                            let session_manager_lock = SESSION_MANAGER.read();
                            let config = &session_manager_lock.settings().headset;
                            ctx.tracking_manager.write().recenter(
                                config.position_recentering_mode,
                                config.rotation_recentering_mode,
                            );

                            let area = packet.unwrap_or(Vec2::new(2.0, 2.0));
                            let wh = area.x * area.y;
                            if wh.is_finite() && wh > 0.0 {
                                info!("Received new playspace with size: {}", area);
                                ctx.events_sender
                                    .send(ServerCoreEvent::PlayspaceSync(area))
                                    .ok();
                            } else {
                                warn!("Received invalid playspace size: {}", area);
                                ctx.events_sender
                                    .send(ServerCoreEvent::PlayspaceSync(Vec2::new(2.0, 2.0)))
                                    .ok();
                            }
                        }
                    }
                    ClientControlPacket::RequestIdr => {
                        if let Some(config) = ctx.decoder_config.lock().clone() {
                            control_sender
                                .lock()
                                .send(&ServerControlPacket::DecoderConfig(config))
                                .ok();
                        }
                        ctx.events_sender.send(ServerCoreEvent::RequestIDR).ok();
                    }
                    ClientControlPacket::VideoErrorReport => {
                        // legacy endpoint. todo: remove
                        if let Some(stats) = &mut *ctx.statistics_manager.write() {
                            stats.report_packet_loss();
                        }
                        ctx.events_sender.send(ServerCoreEvent::RequestIDR).ok();
                    }
                    ClientControlPacket::ViewsConfig(config) => {
                        ctx.events_sender
                            .send(ServerCoreEvent::ViewsConfig(ViewsConfig {
                                local_view_transforms: [
                                    Pose {
                                        position: Vec3::new(-config.ipd_m / 2., 0., 0.),
                                        orientation: Quat::IDENTITY,
                                    },
                                    Pose {
                                        position: Vec3::new(config.ipd_m / 2., 0., 0.),
                                        orientation: Quat::IDENTITY,
                                    },
                                ],
                                fov: config.fov,
                            }))
                            .ok();
                    }
                    ClientControlPacket::Battery(packet) => {
                        ctx.events_sender
                            .send(ServerCoreEvent::Battery(packet.clone()))
                            .ok();

                        if let Some(stats) = &mut *ctx.statistics_manager.write() {
                            stats.report_battery(
                                packet.device_id,
                                packet.gauge_value,
                                packet.is_plugged,
                            );
                        }
                    }
                    ClientControlPacket::Buttons(entries) => {
                        {
                            let session_manager_lock = SESSION_MANAGER.read();
                            if session_manager_lock
                                .settings()
                                .extra
                                .logging
                                .log_button_presses
                            {
                                alvr_events::send_event(EventType::Buttons(
                                    entries
                                        .iter()
                                        .map(|e| ButtonEvent {
                                            path: BUTTON_INFO.get(&e.path_id).map_or_else(
                                                || format!("Unknown (ID: {:#16x})", e.path_id),
                                                |info| info.path.to_owned(),
                                            ),
                                            value: e.value,
                                        })
                                        .collect(),
                                ));
                            }
                        }

                        if let Some(manager) = &mut controller_button_mapping_manager {
                            let button_entries = entries
                                .iter()
                                .flat_map(|entry| manager.map_button(entry))
                                .collect::<Vec<_>>();

                            if !button_entries.is_empty() {
                                ctx.events_sender
                                    .send(ServerCoreEvent::Buttons(button_entries))
                                    .ok();
                            }
                        };
                    }
                    ClientControlPacket::ActiveInteractionProfile { profile_id, .. } => {
                        controller_button_mapping_manager = if let Switch::Enabled(config) =
                            &SESSION_MANAGER.read().settings().headset.controllers
                        {
                            if let Some(mappings) = &config.button_mappings {
                                Some(ButtonMappingManager::new_manual(mappings))
                            } else if let (Some(profile_info), Some(emulation_mode)) = (
                                CONTROLLER_PROFILE_INFO.get(&profile_id),
                                &controllers_emulation_mode,
                            ) {
                                Some(ButtonMappingManager::new_automatic(
                                    &profile_info.button_set,
                                    emulation_mode,
                                    &config.button_mapping_config,
                                ))
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                    }
                    ClientControlPacket::Log { level, message } => {
                        info!("Client {client_hostname}: [{level:?}] {message}")
                    }
                    ClientControlPacket::Reserved(json_string) => {
                        let reserved: ReservedClientControlPacket =
                            match serde_json::from_str(&json_string) {
                                Ok(reserved) => reserved,
                                Err(e) => {
                                    info!(
                                    "Failed to parse reserved packet: {e}. Packet: {json_string}"
                                );
                                    continue;
                                }
                            };

                        match reserved {
                            ReservedClientControlPacket::CustomInteractionProfile {
                                input_ids,
                                ..
                            } => {
                                controller_button_mapping_manager = if let Switch::Enabled(config) =
                                    &SESSION_MANAGER.read().settings().headset.controllers
                                {
                                    if let Some(mappings) = &config.button_mappings {
                                        Some(ButtonMappingManager::new_manual(mappings))
                                    } else {
                                        controllers_emulation_mode.as_ref().map(|emulation_mode| {
                                            ButtonMappingManager::new_automatic(
                                                &input_ids,
                                                emulation_mode,
                                                &config.button_mapping_config,
                                            )
                                        })
                                    }
                                } else {
                                    None
                                };
                            }
                        }
                    }
                    _ => (),
                }

                disconnection_deadline = Instant::now() + KEEPALIVE_TIMEOUT;
            }

            disconnect_notif.notify_one()
        }
    });

    let stream_receive_thread = thread::spawn({
        let disconnect_notif = Arc::clone(&disconnect_notif);
        let client_hostname = client_hostname.clone();
        move || {
            while is_streaming(&client_hostname) {
                match stream_socket.recv() {
                    Ok(()) => (),
                    Err(ConnectionError::TryAgain(_)) => continue,
                    Err(e) => {
                        info!("Client disconnected. Cause: {e}");

                        disconnect_notif.notify_one();

                        return;
                    }
                }
            }
        }
    });

    let lifecycle_check_thread = thread::spawn({
        let disconnect_notif = Arc::clone(&disconnect_notif);
        let client_hostname = client_hostname.clone();
        move || {
            while SESSION_MANAGER
                .read()
                .client_list()
                .get(&client_hostname)
                .is_some_and(|c| c.connection_state == ConnectionState::Streaming)
                && *lifecycle_state.read() == LifecycleState::Resumed
            {
                thread::sleep(STREAMING_RECV_TIMEOUT);
            }

            disconnect_notif.notify_one()
        }
    });

    {
        if initial_settings.connection.enable_on_connect_script {
            let on_connect_script = FILESYSTEM_LAYOUT.get().map(|l| l.connect_script()).unwrap();
            info!(
                "Running on connect script (connect): {}",
                on_connect_script.display()
            );
            if let Err(e) = Command::new(&on_connect_script)
                .env("ACTION", "connect")
                .spawn()
            {
                warn!("Failed to run connect script: {e}");
            }
        }
    }

    if initial_settings.extra.capture.startup_video_recording {
        info!("Creating recording file");
        crate::create_recording_file(&ctx, session_manager_lock.settings());
    }

    info!(
        "[PIPELINE] {client_hostname}: HANDSHAKE COMPLETE, all streaming threads started, total {:?}. Setting the client state to Streaming",
        pipeline_start.elapsed(),
    );

    session_manager_lock.update_client_list(
        client_hostname.clone(),
        ClientListAction::SetConnectionState(ConnectionState::Streaming),
    );

    ctx.events_sender
        .send(ServerCoreEvent::ClientConnected)
        .ok();

    dbg_connection!("connection_pipeline: handshake finished; unlocking streams");
    alvr_common::wait_rwlock(&disconnect_notif, &mut session_manager_lock);
    dbg_connection!("connection_pipeline: Begin connection shutdown");

    info!(
        "[PIPELINE] {client_hostname}: streaming session ended after {:?}, shutting the streaming threads down",
        pipeline_start.elapsed(),
    );

    // This requests shutdown from threads
    *ctx.video_channel_sender.lock() = None;
    *ctx.haptics_sender.lock() = None;

    *ctx.video_recording_file.lock() = None;

    session_manager_lock.update_client_list(
        client_hostname,
        ClientListAction::SetConnectionState(ConnectionState::Disconnecting),
    );

    let enable_on_disconnect_script = session_manager_lock
        .settings()
        .connection
        .enable_on_disconnect_script;
    if enable_on_disconnect_script {
        let on_disconnect_script = FILESYSTEM_LAYOUT
            .get()
            .map(|l| l.disconnect_script())
            .unwrap();
        info!(
            "Running on disconnect script (disconnect): {}",
            on_disconnect_script.display()
        );
        if let Err(e) = Command::new(&on_disconnect_script)
            .env("ACTION", "disconnect")
            .spawn()
        {
            warn!("Failed to run disconnect script: {e}");
        }
    }

    // Allow threads to shutdown correctly
    drop(session_manager_lock);

    // Ensure shutdown of threads
    dbg_connection!("connection_pipeline: Shutdown threads");
    video_send_thread.join().ok();
    game_audio_thread.join().ok();
    microphone_thread.join().ok();
    tracking_receive_thread.join().ok();
    statistics_thread.join().ok();
    real_time_update_thread.join().ok();
    control_receive_thread.join().ok();
    stream_receive_thread.join().ok();
    keepalive_thread.join().ok();
    lifecycle_check_thread.join().ok();

    ctx.events_sender
        .send(ServerCoreEvent::ClientDisconnected)
        .ok();

    dbg_connection!("connection_pipeline: End");

    Ok(())
}
