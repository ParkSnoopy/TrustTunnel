use crate::{http_codec, net_utils, settings, subscription, tls_demultiplexer};
use std::sync::{Arc, RwLock};

pub struct HttpDemux {
    core_settings: Arc<settings::Settings>,
    subscription: Arc<RwLock<Option<subscription::SubscriptionConfig>>>,
}

impl HttpDemux {
    pub const fn new(
        core_settings: Arc<settings::Settings>,
        subscription: Arc<RwLock<Option<subscription::SubscriptionConfig>>>,
    ) -> Self {
        Self {
            core_settings,
            subscription,
        }
    }

    pub fn select(
        &self,
        _protocol: tls_demultiplexer::Protocol,
        request: &http_codec::RequestHeaders,
    ) -> net_utils::Channel {
        match () {
            () if self.check_subscription(request) => net_utils::Channel::Subscription,
            () if self.check_ping(request) => net_utils::Channel::Ping,
            () if self.check_speedtest(request) => net_utils::Channel::Speedtest,
            () if self.check_reverse_proxy_path(request) => net_utils::Channel::ReverseProxy,
            () => net_utils::Channel::Tunnel,
        }
    }

    fn check_subscription(&self, request: &http_codec::RequestHeaders) -> bool {
        let sub = self.subscription.read().unwrap_or_else(|e| {
            log::error!("Recovering poisoned subscription lock: {e}");
            e.into_inner()
        });
        sub.as_ref()
            .is_some_and(|cfg| request.uri.path() == cfg.path)
    }

    fn check_ping(&self, request: &http_codec::RequestHeaders) -> bool {
        if !self.core_settings.main_host_services.ping_enable {
            return false;
        }
        if let Some(path) = self.core_settings.ping_path.as_ref() {
            return request.uri.path().starts_with(path);
        }
        false
    }

    fn check_speedtest(&self, request: &http_codec::RequestHeaders) -> bool {
        if !self.core_settings.main_host_services.speedtest_enable {
            return false;
        }
        if let Some(path) = self.core_settings.speedtest_path.as_ref() {
            return request.uri.path().starts_with(path);
        }
        false
    }

    fn check_reverse_proxy_path(&self, request: &http_codec::RequestHeaders) -> bool {
        if self.core_settings.reverse_proxy.is_none() {
            return false;
        }
        self.core_settings
            .reverse_proxy
            .as_ref()
            .map(|x| x.path_mask.as_str())
            .is_some_and(|x| request.uri.path().starts_with(x))
    }
}
