use std::{
    self,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use fnv::FnvHashMap;
use futures::Future;
use pb::error_metadata::ErrorMetadataStatusExt;
use pb_extras::ReflectionService;
use sentry::integrations::tower as sentry_tower;
use tokio::net::TcpSocket;
use tonic::{
    server::NamedService,
    service::Routes,
    Response,
    Status,
};
use tonic_health::{
    server::{
        health_reporter,
        HealthReporter,
    },
    ServingStatus,
};
use tonic_middleware::MiddlewareLayer;
use tower::ServiceBuilder;

use crate::knobs::HTTP_SERVER_TCP_BACKLOG;

mod middleware;

// maps the full route `/service.Service/Method` to just `Method`
type KnownMethods = FnvHashMap<String, &'static str>;
pub struct ConvexGrpcService {
    routes: Routes,
    known_methods: KnownMethods,
    health_reporter: HealthReporter,
    service_names: Vec<&'static str>,
}

impl ConvexGrpcService {
    pub fn new() -> Self {
        let (health_reporter, health_service) = health_reporter();
        let routes = Routes::new(health_service);
        Self {
            routes,
            known_methods: FnvHashMap::default(),
            health_reporter,
            service_names: Vec::new(),
        }
    }

    pub fn add_service<S>(mut self, service: S) -> Self
    where
        S: tower::Service<
                http::Request<tonic::body::Body>,
                Response = http::Response<tonic::body::Body>,
                Error = Infallible,
            > + ReflectionService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        self.routes = self.routes.add_service(service);
        // Gather all service names so we can mark them all as healthy and print one
        // line with all names when we start serving.
        let service_name = <S as NamedService>::NAME;
        self.service_names.push(service_name);
        for method_name in S::METHODS {
            self.known_methods
                .insert(format!("/{service_name}/{method_name}"), method_name);
        }
        self
    }

    pub async fn serve<F>(self, addr: SocketAddr, shutdown: F) -> anyhow::Result<()>
    where
        F: Future<Output = ()>,
    {
        let known_methods = Arc::new(self.known_methods);
        let convex_layers = ServiceBuilder::new()
            .layer(MiddlewareLayer::new(middleware::LoggingMiddleware::new(
                known_methods.clone(),
            )))
            .layer(crate::fastrace_helpers::layer::TraceparentReceivingLayer)
            .layer_fn(|s| middleware::TokioInstrumentationService::new(known_methods.clone(), s))
            .layer(sentry_tower::NewSentryLayer::new_from_top())
            .layer(sentry_tower::SentryHttpLayer::with_transaction());

        let protocol = match addr.ip() {
            IpAddr::V4(_) => "ipv4",
            IpAddr::V6(_) => "ipv6",
        };
        tracing::info!(
            "gRPC services {} listening on {}://{}",
            self.service_names.join(","),
            protocol,
            addr
        );
        for service_name in self.service_names {
            self.health_reporter
                .set_service_status(service_name, ServingStatus::Serving)
                .await;
        }
        // Set SO_REUSEADDR and a bounded TCP accept backlog for our server's listening
        // socket.
        let socket = match addr.ip() {
            IpAddr::V4(_) => TcpSocket::new_v4()?,
            IpAddr::V6(_) => {
                let socket = TcpSocket::new_v6()?;
                // Enable dual-stack mode (accept both IPv4 and IPv6)
                socket.set_ipv6_only(false)?;
                socket
            }
        };
        socket.set_reuseaddr(true)?;
        socket.set_nodelay(true)?;
        socket.bind(addr)?;

        let listener = socket.listen(*HTTP_SERVER_TCP_BACKLOG)?;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        tonic::transport::Server::builder()
            .layer(convex_layers)
            .add_routes(self.routes)
            .serve_with_incoming_shutdown(incoming, shutdown)
            .await?;
        tracing::info!("GRPC server shutdown complete");
        Ok(())
    }
}

pub fn handle_response<T>(response: Result<Response<T>, Status>) -> anyhow::Result<T> {
    match response {
        Ok(response) => Ok(response.into_inner()),
        Err(status) => Err(status.into_anyhow()),
    }
}
