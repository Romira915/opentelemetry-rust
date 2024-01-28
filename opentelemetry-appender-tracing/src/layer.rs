use opentelemetry::{
    logs::{LogRecord, Logger, LoggerProvider, Severity},
    Context, KeyValue,
};
use std::borrow::Cow;
use tracing_subscriber::Layer;

const INSTRUMENTATION_LIBRARY_NAME: &str = "opentelemetry-appender-tracing";

/// Visitor to record the fields from the event record.
struct EventVisitor<'a> {
    log_record: &'a mut LogRecord,
}

impl<'a> tracing::field::Visit for EventVisitor<'a> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.log_record.body = Some(format!("{value:?}").into());
        } else if let Some(ref mut vec) = self.log_record.attributes {
            vec.push((field.name().into(), format!("{value:?}").into()));
        } else {
            let vec = vec![(field.name().into(), format!("{value:?}").into())];
            self.log_record.attributes = Some(vec);
        }
    }

    fn record_str(&mut self, field: &tracing_core::Field, value: &str) {
        if let Some(ref mut vec) = self.log_record.attributes {
            vec.push((field.name().into(), value.to_owned().into()));
        } else {
            let vec = vec![(field.name().into(), value.to_owned().into())];
            self.log_record.attributes = Some(vec);
        }
    }

    fn record_bool(&mut self, field: &tracing_core::Field, value: bool) {
        if let Some(ref mut vec) = self.log_record.attributes {
            vec.push((field.name().into(), value.into()));
        } else {
            let vec = vec![(field.name().into(), value.into())];
            self.log_record.attributes = Some(vec);
        }
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        if let Some(ref mut vec) = self.log_record.attributes {
            vec.push((field.name().into(), value.into()));
        } else {
            let vec = vec![(field.name().into(), value.into())];
            self.log_record.attributes = Some(vec);
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if let Some(ref mut vec) = self.log_record.attributes {
            vec.push((field.name().into(), value.into()));
        } else {
            let vec = vec![(field.name().into(), value.into())];
            self.log_record.attributes = Some(vec);
        }
    }

    // TODO: Remaining field types from AnyValue : Bytes, ListAny, Boolean
}

pub struct OpenTelemetryTracingBridge<P, L>
where
    P: LoggerProvider<Logger = L> + Send + Sync,
    L: Logger + Send + Sync,
{
    logger: L,
    _phantom: std::marker::PhantomData<P>, // P is not used.
}

impl<P, L> OpenTelemetryTracingBridge<P, L>
where
    P: LoggerProvider<Logger = L> + Send + Sync,
    L: Logger + Send + Sync,
{
    pub fn new(provider: &P) -> Self {
        OpenTelemetryTracingBridge {
            logger: provider.versioned_logger(
                INSTRUMENTATION_LIBRARY_NAME,
                Some(Cow::Borrowed(env!("CARGO_PKG_VERSION"))),
                None,
                None,
            ),
            _phantom: Default::default(),
        }
    }
}

impl<S, P, L> Layer<S> for OpenTelemetryTracingBridge<P, L>
where
    S: tracing::Subscriber,
    P: LoggerProvider<Logger = L> + Send + Sync + 'static,
    L: Logger + Send + Sync + 'static,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let meta = event.metadata();
        let mut log_record: LogRecord = LogRecord::default();
        log_record.severity_number = Some(map_severity_to_otel_severity(meta.level().as_str()));
        log_record.severity_text = Some(meta.level().to_string().into());
        if let Some(ref mut vec) = log_record.attributes {
            vec.push(("level".into(), meta.level().to_string().into()));
        } else {
            let vec = vec![("level".into(), meta.level().to_string().into())];
            log_record.attributes = Some(vec);
        }
        println!("{:?}", find_current_trace_id());
        if let (Some(vec), Some(trace_id)) =
            (log_record.attributes.as_mut(), find_current_trace_id())
        {
            vec.push(("trace.id".into(), trace_id.into()));
        }
        if let (Some(attributes), Some(span_id)) = (
            log_record.attributes.as_mut(),
            tracing::Span::current().id(),
        ) {
            attributes.push(("span.id".into(), span_id.into_u64().to_string().into()));
        }

        // Not populating ObservedTimestamp, instead relying on OpenTelemetry
        // API to populate it with current time.

        let mut visitor = EventVisitor {
            log_record: &mut log_record,
        };
        event.record(&mut visitor);
        self.logger.emit(log_record);
    }

    #[cfg(feature = "logs_level_enabled")]
    fn event_enabled(
        &self,
        _event: &tracing_core::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        let severity = map_severity_to_otel_severity(_event.metadata().level().as_str());
        self.logger
            .event_enabled(severity, _event.metadata().target())
    }
}

fn map_severity_to_otel_severity(level: &str) -> Severity {
    match level {
        "INFO" => Severity::Info,
        "DEBUG" => Severity::Debug,
        "TRACE" => Severity::Trace,
        "WARN" => Severity::Warn,
        "ERROR" => Severity::Error,
        _ => Severity::Info, // won't reach here
    }
}

#[inline]
#[must_use]
pub fn find_trace_id(context: &Context) -> Option<String> {
    use opentelemetry::trace::TraceContextExt;

    let span = context.span();
    let span_context = span.span_context();
    span_context
        .is_valid()
        .then(|| span_context.trace_id().to_string())

    // #[cfg(not(any(
    //     feature = "opentelemetry_0_17",
    //     feature = "opentelemetry_0_18",
    //     feature = "opentelemetry_0_19"
    // )))]
    // let trace_id = span.context().span().span_context().trace_id().to_hex();

    // #[cfg(any(
    //     feature = "opentelemetry_0_17",
    //     feature = "opentelemetry_0_18",
    //     feature = "opentelemetry_0_19"
    // ))]
    // let trace_id = {
    //     let id = span.context().span().span_context().trace_id();
    //     format!("{:032x}", id)
    // };
}

#[inline]
#[must_use]
pub fn find_current_context() -> Context {
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    // let context = opentelemetry::Context::current();
    // OpenTelemetry Context is propagation inside code is done via tracing crate
    tracing::Span::current().context()
}

#[inline]
#[must_use]
pub fn find_current_trace_id() -> Option<String> {
    find_trace_id(&find_current_context())
}
