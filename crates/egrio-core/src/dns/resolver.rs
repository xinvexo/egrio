use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use tokio::time::{timeout, Duration};

#[cfg(test)]
use crate::dns::fake_ip::{project_ipv4_to_ipv6, FakeDnsStore};
use crate::dns::policy::{DnsDecisionAction, DnsQueryInput, DnsRecordType};
use crate::runtime::NativeCoreRuntime;

const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_SVCB: u16 = 64;
const DNS_TYPE_HTTPS: u16 = 65;
const DNS_TYPE_SRV: u16 = 33;
const DNS_TYPE_TXT: u16 = 16;
#[cfg(test)]
const DNS_RESPONSE_FLAG_TC: u16 = 0x0200;
const DNS_RCODE_NOERROR: u16 = 0;
const DNS_RCODE_NXDOMAIN: u16 = 3;
/// Virtual address answers use a short TTL; mappings remain owned by the
/// session because client caches can keep them beyond the advertised TTL.
const FAKE_IP_TTL_SECONDS: u32 = 1;
/// A short TTL lets changed hosts mappings reach applications promptly.
const HOSTS_TTL_SECONDS: u32 = 10;
const DNS_UDP_MAX_RESPONSE_BYTES: usize = 512;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsQueryTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsQuestion {
    request: hickory_proto::op::Message,
    domain: String,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsAnswer {
    qtype: u16,
    qclass: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

pub(crate) async fn resolve_dns_query_payload(
    runtime: &NativeCoreRuntime,
    payload: &[u8],
    process_name: Option<String>,
    process_path: Option<String>,
) -> Result<Vec<u8>, String> {
    resolve_dns_query_payload_for_transport(
        runtime,
        payload,
        process_name,
        process_path,
        DnsQueryTransport::Udp,
    )
    .await
}

pub(crate) async fn resolve_dns_query_payload_for_transport(
    runtime: &NativeCoreRuntime,
    payload: &[u8],
    process_name: Option<String>,
    process_path: Option<String>,
    transport: DnsQueryTransport,
) -> Result<Vec<u8>, String> {
    match plan_dns_query(runtime, payload, process_name, process_path, transport)? {
        DnsQueryPlan::Answered(reply) => Ok(reply),
        DnsQueryPlan::Upstream(query) => query.exchange(runtime).await,
    }
}

/// How a query gets its reply: made on the spot from the DNS decision, or
/// from an upstream exchange, the only part that waits on the network.
pub(crate) enum DnsQueryPlan {
    Answered(Vec<u8>),
    Upstream(UpstreamQuery),
}

/// A query the DNS decision sends to an upstream.
pub(crate) struct UpstreamQuery {
    request: hickory_proto::op::Message,
    prepared: super::service::PreparedApplicationQuery,
    transport: DnsQueryTransport,
}

impl UpstreamQuery {
    pub(crate) async fn exchange(self, runtime: &NativeCoreRuntime) -> Result<Vec<u8>, String> {
        let Self {
            request,
            prepared,
            transport,
        } = self;
        let cancel = runtime.connection_cancellation();
        let reply = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err("DNS query cancelled by policy change".into()),
            reply = runtime.dns_service().exchange_application_query(request.clone(), prepared) => reply,
        };
        let mut reply = reply.unwrap_or_else(|_| {
            crate::dns::wire::response(&request, hickory_proto::op::ResponseCode::ServFail)
        });
        let mut encoded = crate::dns::wire::encode(&reply)?;
        if transport == DnsQueryTransport::Udp && encoded.len() > usize::from(request.max_payload())
        {
            reply.answers.clear();
            reply.authorities.clear();
            reply.additionals.clear();
            reply.metadata.truncation = true;
            encoded = crate::dns::wire::encode(&reply)?;
        }
        Ok(encoded)
    }
}

/// Decides a query without waiting on anything: blocked, Fake-IP, empty and
/// loopback answers are made here, so the packet pump can return them at
/// once; a query bound for an upstream comes back as [`DnsQueryPlan::Upstream`].
pub(crate) fn plan_dns_query(
    runtime: &NativeCoreRuntime,
    payload: &[u8],
    process_name: Option<String>,
    process_path: Option<String>,
    transport: DnsQueryTransport,
) -> Result<DnsQueryPlan, String> {
    let question = match parse_dns_query(payload) {
        Ok(question) => question,
        Err(error) => {
            if payload.len() < 12 || payload[2] & 0x80 != 0 {
                return Err(error);
            }
            let opcode = (payload[2] >> 3) & 0x0f;
            let mut request = hickory_proto::op::Message::new(
                u16::from_be_bytes([payload[0], payload[1]]),
                hickory_proto::op::MessageType::Query,
                hickory_proto::op::OpCode::from_u8(opcode),
            );
            request.metadata.recursion_desired = payload[2] & 1 != 0;
            let code = if opcode == 0 {
                hickory_proto::op::ResponseCode::FormErr
            } else {
                hickory_proto::op::ResponseCode::NotImp
            };
            return crate::dns::wire::encode(&crate::dns::wire::response(&request, code))
                .map(DnsQueryPlan::Answered);
        }
    };
    let record_type = dns_record_type(question.qtype);
    let prepared = runtime
        .dns_service()
        .prepare_application_query(&DnsQueryInput {
            query_class: question.qclass,
            domain: question.domain.clone(),
            record_type,
            process_name,
            process_path,
        });

    let reply = match prepared.action {
        DnsDecisionAction::Block => {
            build_dns_response_for_transport(&question, DNS_RCODE_NXDOMAIN, Vec::new(), transport)
        }
        DnsDecisionAction::FakeIp => {
            let (rcode, answers) = match fake_ip_answers(runtime, &question) {
                Ok(answers) => (DNS_RCODE_NOERROR, answers),
                Err(_) => (2, Vec::new()),
            };
            build_dns_response_for_transport(&question, rcode, answers, transport)
        }
        DnsDecisionAction::Empty => {
            build_dns_response_for_transport(&question, DNS_RCODE_NOERROR, Vec::new(), transport)
        }
        DnsDecisionAction::Loopback => build_dns_response_for_transport(
            &question,
            DNS_RCODE_NOERROR,
            loopback_answers(runtime, &question),
            transport,
        ),
        DnsDecisionAction::Hosts => build_dns_response_for_transport(
            &question,
            DNS_RCODE_NOERROR,
            hosts_answers(runtime, &question),
            transport,
        ),
        DnsDecisionAction::Resolve => {
            return Ok(DnsQueryPlan::Upstream(UpstreamQuery {
                request: crate::dns::wire::decode(payload)?,
                prepared,
                transport,
            }));
        }
    };
    Ok(DnsQueryPlan::Answered(reply))
}

pub(crate) fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// `localhost` and the names under it, which resolve to the loopback address
/// without any upstream (RFC 6761 section 6.3).
pub(crate) fn is_localhost_name(domain: &str) -> bool {
    const LOCALHOST: &[u8] = b"localhost";
    let name = domain.trim().trim_end_matches('.').as_bytes();
    let Some(before) = name.len().checked_sub(LOCALHOST.len()) else {
        return false;
    };
    name[before..].eq_ignore_ascii_case(LOCALHOST) && (before == 0 || name[before - 1] == b'.')
}

fn loopback_answers(runtime: &NativeCoreRuntime, question: &DnsQuestion) -> Vec<DnsAnswer> {
    let rdata = match question.qtype {
        _ if question.qclass != DNS_CLASS_IN => return Vec::new(),
        DNS_TYPE_A => Ipv4Addr::LOCALHOST.octets().to_vec(),
        DNS_TYPE_AAAA if runtime.egress().ipv6_enabled() => Ipv6Addr::LOCALHOST.octets().to_vec(),
        _ => return Vec::new(),
    };
    vec![DnsAnswer {
        qtype: question.qtype,
        qclass: DNS_CLASS_IN,
        ttl: 0,
        rdata,
    }]
}

/// The mapped addresses of the question's family; none of it is an empty
/// answer, never a question to an upstream.
fn hosts_answers(runtime: &NativeCoreRuntime, question: &DnsQuestion) -> Vec<DnsAnswer> {
    if question.qclass != DNS_CLASS_IN {
        return Vec::new();
    }
    let Some(addresses) = runtime.dns_service().hosts(&question.domain) else {
        return Vec::new();
    };
    addresses
        .iter()
        .filter_map(|address| match (question.qtype, address) {
            (DNS_TYPE_A, IpAddr::V4(v4)) => Some(v4.octets().to_vec()),
            (DNS_TYPE_AAAA, IpAddr::V6(v6)) => Some(v6.octets().to_vec()),
            _ => None,
        })
        .map(|rdata| DnsAnswer {
            qtype: question.qtype,
            qclass: DNS_CLASS_IN,
            ttl: HOSTS_TTL_SECONDS,
            rdata,
        })
        .collect()
}

fn fake_ip_answers(
    runtime: &NativeCoreRuntime,
    question: &DnsQuestion,
) -> Result<Vec<DnsAnswer>, String> {
    if question.qclass != DNS_CLASS_IN {
        return Ok(Vec::new());
    }

    match question.qtype {
        DNS_TYPE_A => {
            let ip = runtime.fake_dns().allocate_ipv4(&question.domain)?;
            Ok(vec![DnsAnswer {
                qtype: DNS_TYPE_A,
                qclass: DNS_CLASS_IN,
                ttl: FAKE_IP_TTL_SECONDS,
                rdata: ip.octets().to_vec(),
            }])
        }
        DNS_TYPE_AAAA if runtime.egress().ipv6_enabled() => {
            let ip = runtime.fake_dns().allocate_ipv6(&question.domain)?;
            Ok(vec![DnsAnswer {
                qtype: DNS_TYPE_AAAA,
                qclass: DNS_CLASS_IN,
                ttl: FAKE_IP_TTL_SECONDS,
                rdata: ip.octets().to_vec(),
            }])
        }
        _ => Ok(Vec::new()),
    }
}

fn parse_dns_query(payload: &[u8]) -> Result<DnsQuestion, String> {
    let request = crate::dns::wire::decode(payload)?;
    crate::dns::wire::validate_request(&request)?;
    let question = request.queries.first().expect("validated DNS question");
    let domain = normalize_domain(&question.name().to_utf8());
    let qtype = u16::from(question.query_type());
    let qclass = u16::from(question.query_class());
    Ok(DnsQuestion {
        request,
        domain,
        qtype,
        qclass,
    })
}

#[cfg(test)]
fn build_dns_response(question: &DnsQuestion, rcode: u16, answers: Vec<DnsAnswer>) -> Vec<u8> {
    build_dns_response_for_transport(question, rcode, answers, DnsQueryTransport::Udp)
}

fn build_dns_response_for_transport(
    question: &DnsQuestion,
    rcode: u16,
    answers: Vec<DnsAnswer>,
    transport: DnsQueryTransport,
) -> Vec<u8> {
    let response = encode_dns_response(question, rcode, &answers, false);
    if transport == DnsQueryTransport::Tcp || response.len() <= DNS_UDP_MAX_RESPONSE_BYTES {
        return response;
    }

    // Too large for a classic 512-byte UDP response: drop the answers and set
    // the TC bit so the client retries the query over TCP.
    encode_dns_response(question, rcode, &[], true)
}

fn encode_dns_response(
    question: &DnsQuestion,
    rcode: u16,
    answers: &[DnsAnswer],
    truncated: bool,
) -> Vec<u8> {
    use hickory_proto::rr::{
        rdata::{A, AAAA},
        RData, Record,
    };
    let mut message = crate::dns::wire::response(&question.request, rcode.into());
    message.metadata.truncation = truncated;
    let name = question
        .request
        .queries
        .first()
        .expect("validated DNS question")
        .name();
    for answer in answers {
        let data = match (answer.qtype, answer.rdata.as_slice()) {
            (DNS_TYPE_A, [a, b, c, d]) => RData::A(A(Ipv4Addr::new(*a, *b, *c, *d))),
            (DNS_TYPE_AAAA, data) if data.len() == 16 => RData::AAAA(AAAA(Ipv6Addr::from(
                <[u8; 16]>::try_from(data).expect("IPv6 RDATA"),
            ))),
            _ => continue,
        };
        let mut record = Record::from_rdata(name.clone(), answer.ttl, data);
        record.dns_class = hickory_proto::rr::DNSClass::from(answer.qclass);
        message.add_answer(record);
    }
    crate::dns::wire::encode(&message).expect("bounded synthetic DNS response")
}

fn dns_record_type(qtype: u16) -> DnsRecordType {
    match qtype {
        DNS_TYPE_A => DnsRecordType::A,
        DNS_TYPE_AAAA => DnsRecordType::Aaaa,
        DNS_TYPE_SVCB => DnsRecordType::Svcb,
        DNS_TYPE_HTTPS => DnsRecordType::Https,
        DNS_TYPE_SRV => DnsRecordType::Srv,
        DNS_TYPE_TXT => DnsRecordType::Txt,
        _ => DnsRecordType::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use crate::profile::{ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile};
    use crate::runtime::NativeCoreRuntime;

    #[tokio::test]
    async fn unsupported_opcode_and_malformed_question_receive_protocol_errors() {
        use hickory_proto::op::{Message, OpCode, ResponseCode};
        let runtime = NativeCoreRuntime::compile(&proxy_profile());
        let empty = Message::new(0x1234, hickory_proto::op::MessageType::Query, OpCode::Query);
        let mut unsupported =
            crate::dns::wire::query("status.test", hickory_proto::rr::RecordType::A).unwrap();
        unsupported.metadata.op_code = OpCode::Status;
        for (query, code) in [
            (empty, ResponseCode::FormErr),
            (unsupported, ResponseCode::NotImp),
        ] {
            let response = resolve_dns_query_payload(
                &runtime,
                &crate::dns::wire::encode(&query).unwrap(),
                None,
                None,
            )
            .await
            .unwrap();
            let response = crate::dns::wire::decode(&response).unwrap();
            assert_eq!(response.response_code, code);
            assert_eq!(response.id, query.id);
            assert_eq!(response.op_code, query.op_code);
        }
    }

    #[tokio::test]
    async fn live_ipv6_switch_changes_aaaa_answers_without_losing_fake_mapping() {
        let core = crate::NativeCoreDevice::compile(&proxy_profile());
        let query = dns_query(0x1234, "policy.example", DNS_TYPE_AAAA);
        let disabled = core
            .resolve_dns_query_payload(&query, None, None)
            .await
            .unwrap();
        assert_eq!(u16::from_be_bytes([disabled[6], disabled[7]]), 0);
        let prepared = core
            .prepare_policy_update(&[crate::CorePolicyUpdate::Ipv6Enabled(true)])
            .unwrap();
        let report = core.apply_policy_update(prepared).unwrap();
        assert!(
            report
                .retirement
                .wait(std::time::Duration::from_secs(1))
                .await
        );
        let enabled = core
            .resolve_dns_query_payload(&query, None, None)
            .await
            .unwrap();
        assert_eq!(u16::from_be_bytes([enabled[6], enabled[7]]), 1);
        let mapping = enabled[enabled.len() - 16..].to_vec();
        let prepared = core
            .prepare_policy_update(&[crate::CorePolicyUpdate::Ipv6Enabled(false)])
            .unwrap();
        core.apply_policy_update(prepared).unwrap();
        let disabled = core
            .resolve_dns_query_payload(&query, None, None)
            .await
            .unwrap();
        assert_eq!(u16::from_be_bytes([disabled[6], disabled[7]]), 0);
        let prepared = core
            .prepare_policy_update(&[crate::CorePolicyUpdate::Ipv6Enabled(true)])
            .unwrap();
        core.apply_policy_update(prepared).unwrap();
        let enabled = core
            .resolve_dns_query_payload(&query, None, None)
            .await
            .unwrap();
        assert_eq!(&enabled[enabled.len() - 16..], mapping.as_slice());
    }

    #[tokio::test]
    async fn proxied_a_query_returns_fake_ip_and_records_reverse_mapping() {
        let runtime = NativeCoreRuntime::compile(&proxy_profile());
        let query = dns_query(0x1234, "example.com", DNS_TYPE_A);

        let response = resolve_dns_query_payload(&runtime, &query, None, None)
            .await
            .expect("DNS query resolves");
        let fake_ip = first_a_answer(&response).expect("fake A answer");
        assert_eq!(first_answer_ttl(&response), Some(FAKE_IP_TTL_SECONDS));

        assert!(matches!(fake_ip.octets(), [198, 18 | 19, _, _]));
        assert_eq!(
            runtime.fake_dns().lookup_ipv4(fake_ip).as_deref(),
            Some("example.com")
        );
        assert_eq!(
            runtime.resolve_packet_destination_host(IpAddr::V4(fake_ip)),
            "example.com"
        );
    }

    #[tokio::test]
    async fn proxied_aaaa_query_returns_paired_fake_ip_when_ipv6_enabled() {
        let runtime = NativeCoreRuntime::compile_with_egress(
            &proxy_profile(),
            crate::NativeCoreEgressConfig {
                ipv6_enabled: true,
                ..crate::NativeCoreEgressConfig::default()
            },
        );
        let a_response = resolve_dns_query_payload(
            &runtime,
            &dns_query(0x1234, "example.com", DNS_TYPE_A),
            None,
            None,
        )
        .await
        .expect("A query resolves");
        let a = first_a_answer(&a_response).expect("fake A answer");
        let aaaa_response = resolve_dns_query_payload(
            &runtime,
            &dns_query(0x1235, "example.com", DNS_TYPE_AAAA),
            None,
            None,
        )
        .await
        .expect("AAAA query resolves");
        let aaaa = first_aaaa_answer(&aaaa_response).expect("fake AAAA answer");
        assert_eq!(first_answer_ttl(&aaaa_response), Some(FAKE_IP_TTL_SECONDS));

        assert_eq!(aaaa, project_ipv4_to_ipv6(a));
        assert_eq!(
            runtime.fake_dns().lookup_ipv6(aaaa).as_deref(),
            Some("example.com")
        );
        assert_eq!(
            runtime.resolve_packet_destination_host(IpAddr::V6(aaaa)),
            "example.com"
        );
        assert_eq!(runtime.fake_dns().len(), 1);
    }

    #[test]
    fn inactive_fake_range_does_not_claim_real_addresses_but_retains_issued_mappings() {
        use crate::dns::config::DnsMode;
        let address: IpAddr = "10.42.1.1".parse().unwrap();
        let ipv6 = IpAddr::V6(project_ipv4_to_ipv6("10.42.1.1".parse().unwrap()));
        for (enabled, mode) in [
            (false, DnsMode::FakeIp),
            (true, DnsMode::RedirHost),
            (false, DnsMode::RedirHost),
        ] {
            let mut profile = proxy_profile();
            profile.dns.enabled = enabled;
            profile.dns.enhanced_mode = mode;
            profile.dns.fake_ip_range = "10.42.0.1/16".parse().unwrap();
            let runtime = NativeCoreRuntime::compile(&profile);
            for ip in [address, ipv6] {
                assert!(!runtime.is_fake_range_target(ip));
                assert!(!runtime.is_stale_fake_target(ip));
                assert_eq!(runtime.resolve_packet_destination_host(ip), ip.to_string());
            }
            assert!(runtime
                .fake_dns()
                .allocate_ipv4("disabled.example")
                .is_err());
        }

        let mut profile = proxy_profile();
        profile.dns.fake_ip_range = "10.42.0.1/16".parse().unwrap();
        let core = crate::NativeCoreDevice::compile(&profile);
        let issued = core
            .pinned_runtime()
            .fake_dns()
            .allocate_ipv4("cached.example")
            .unwrap();
        for (enabled, mode) in [(false, DnsMode::FakeIp), (true, DnsMode::RedirHost)] {
            profile.dns.enabled = enabled;
            profile.dns.enhanced_mode = mode;
            core.apply_profile(&profile);
            let runtime = core.pinned_runtime();
            assert_eq!(
                runtime
                    .fake_dns_domain_for_ip(IpAddr::V4(issued))
                    .as_deref(),
                Some("cached.example")
            );
            assert!(runtime.is_fake_range_target(IpAddr::V4(issued)));
            assert!(!runtime.is_stale_fake_target(IpAddr::V4(issued)));
            assert!(!runtime.is_fake_range_target("10.42.0.1".parse().unwrap()));
        }
        core.close();
    }

    #[tokio::test]
    async fn configured_fake_pool_survives_reload_and_exhaustion_returns_servfail() {
        let mut profile = proxy_profile();
        profile.dns.fake_ip_range = "10.42.0.1/30".parse().unwrap();
        let core = crate::NativeCoreDevice::compile_with_egress(
            &profile,
            crate::NativeCoreEgressConfig {
                ipv6_enabled: true,
                ..Default::default()
            },
        );
        let a_query = dns_query(0x1234, "retained.example", DNS_TYPE_A);
        let aaaa_query = dns_query(0x1235, "retained.example", DNS_TYPE_AAAA);
        let before = core
            .resolve_dns_query_payload(&a_query, None, None)
            .await
            .unwrap();
        let old_ip = first_a_answer(&before).unwrap();
        assert_eq!(old_ip, Ipv4Addr::new(10, 42, 0, 2));
        let before_v6 = core
            .resolve_dns_query_payload(&aaaa_query, None, None)
            .await
            .unwrap();
        let old_v6 = first_aaaa_answer(&before_v6).unwrap();
        assert_eq!(old_v6, project_ipv4_to_ipv6(old_ip));

        profile.dns.fake_ip_range = "10.43.0.1/30".parse().unwrap();
        core.apply_profile(&profile);
        let after = core
            .resolve_dns_query_payload(&a_query, None, None)
            .await
            .unwrap();
        let new_ip = first_a_answer(&after).unwrap();
        assert_eq!(new_ip, Ipv4Addr::new(10, 43, 0, 2));
        let after_v6 = core
            .resolve_dns_query_payload(&aaaa_query, None, None)
            .await
            .unwrap();
        assert_eq!(
            first_aaaa_answer(&after_v6),
            Some(project_ipv4_to_ipv6(new_ip))
        );
        let runtime = core.pinned_runtime();
        for ip in [IpAddr::V4(old_ip), IpAddr::V6(old_v6), IpAddr::V4(new_ip)] {
            assert_eq!(
                runtime.fake_dns_domain_for_ip(ip).as_deref(),
                Some("retained.example")
            );
            assert!(runtime.is_fake_range_target(ip));
            assert!(!runtime.is_stale_fake_target(ip));
        }
        assert!(runtime.is_stale_fake_target("10.43.0.1".parse().unwrap()));
        assert!(!runtime.is_fake_range_target("198.18.0.1".parse().unwrap()));
        assert_eq!(runtime.fake_dns().len(), 2);

        let exhausted = core
            .resolve_dns_query_payload(
                &dns_query(0x1236, "unallocated.example", DNS_TYPE_A),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(exhausted[3] & 0x0f, 2);
        assert_eq!(u16::from_be_bytes([exhausted[6], exhausted[7]]), 0);
        assert_eq!(
            runtime
                .fake_dns_domain_for_ip(IpAddr::V4(new_ip))
                .as_deref(),
            Some("retained.example")
        );
        core.close();
    }

    #[tokio::test]
    async fn proxied_aaaa_query_returns_empty_noerror_when_ipv6_disabled() {
        let runtime = NativeCoreRuntime::compile(&proxy_profile());
        let query = dns_query(0x4241, "example.com", DNS_TYPE_AAAA);

        let response = resolve_dns_query_payload(&runtime, &query, None, None)
            .await
            .expect("DNS query resolves");

        assert_eq!(response[3] & 0x0f, DNS_RCODE_NOERROR as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(runtime.fake_dns().len(), 0);
    }

    #[tokio::test]
    async fn reject_route_returns_nxdomain() {
        let mut profile = proxy_profile();
        profile.rules = vec![RouteRule {
            kind: RuleKind::DomainSuffix,
            payload: Some("ads.example"),
            outbound: "REJECT",
            no_resolve: false,
        }]
        .into();
        let runtime = NativeCoreRuntime::compile(&profile);
        let query = dns_query(0x1234, "track.ads.example", DNS_TYPE_A);

        let response = resolve_dns_query_payload(&runtime, &query, None, None)
            .await
            .expect("DNS query resolves");

        assert_eq!(response[3] & 0x0f, DNS_RCODE_NXDOMAIN as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[tokio::test]
    async fn direct_aaaa_query_returns_empty_noerror_when_ipv6_disabled() {
        let mut profile = proxy_profile();
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "DIRECT",
            no_resolve: false,
        }]
        .into();
        // Default egress config keeps IPv6 disabled, so the AAAA short-circuit
        // must answer without touching any resolver.
        let runtime = NativeCoreRuntime::compile(&profile);
        let query = dns_query(0x4242, "example.com", DNS_TYPE_AAAA);

        let response = resolve_dns_query_payload(&runtime, &query, None, None)
            .await
            .expect("DNS query resolves");

        assert_eq!(response[3] & 0x0f, DNS_RCODE_NOERROR as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[tokio::test]
    async fn direct_wire_answers_preserve_and_age_the_upstream_ttl() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::net::UdpSocket;

        for qtype in [DNS_TYPE_A, DNS_TYPE_AAAA] {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let received = Arc::new(AtomicUsize::new(0));
            let count = received.clone();
            let task = tokio::spawn(async move {
                let mut query = [0; 512];
                loop {
                    let (length, peer) = server.recv_from(&mut query).await.unwrap();
                    count.fetch_add(1, Ordering::SeqCst);
                    let question = parse_dns_query(&query[..length]).unwrap();
                    let response = build_dns_response(
                        &question,
                        DNS_RCODE_NOERROR,
                        vec![DnsAnswer {
                            qtype,
                            qclass: DNS_CLASS_IN,
                            ttl: if question.domain == "zero.ttl.test" {
                                0
                            } else {
                                5
                            },
                            rdata: if qtype == DNS_TYPE_A {
                                vec![192, 0, 2, 1]
                            } else {
                                "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec()
                            },
                        }],
                    );
                    server.send_to(&response, peer).await.unwrap();
                }
            });
            let runtime = NativeCoreRuntime::compile_with_egress(
                &direct_profile(),
                crate::NativeCoreEgressConfig {
                    dns_servers: vec![server_addr],
                    ipv6_enabled: true,
                    ..Default::default()
                },
            );
            let query = dns_query(0x1234, "ttl.test", qtype);
            let first = resolve_dns_query_payload(&runtime, &query, None, None)
                .await
                .unwrap();
            assert_eq!(first_answer_ttl(&first), Some(5));
            tokio::time::pause();
            tokio::time::advance(Duration::from_millis(2250)).await;
            let cached = resolve_dns_query_payload(&runtime, &query, None, None)
                .await
                .unwrap();
            assert_eq!(
                first_answer_ttl(&cached),
                Some(2),
                "remaining TTL is rounded down"
            );
            tokio::time::advance(Duration::from_millis(2500)).await;
            let almost_expired = resolve_dns_query_payload(&runtime, &query, None, None)
                .await
                .unwrap();
            assert_eq!(first_answer_ttl(&almost_expired), Some(0));
            assert_eq!(
                received.load(Ordering::SeqCst),
                1,
                "both aged replies use the original cache entry"
            );
            tokio::time::resume();
            let zero_query = dns_query(0x1235, "zero.ttl.test", qtype);
            let zero = resolve_dns_query_payload(&runtime, &zero_query, None, None)
                .await
                .unwrap();
            assert_eq!(first_answer_ttl(&zero), Some(0));
            task.abort();
        }
    }

    #[tokio::test]
    async fn direct_dns_response_codes_reach_the_client_without_becoming_timeouts() {
        use tokio::net::UdpSocket;
        for rcode in 0..=15 {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let mut query = [0; 512];
                let (length, peer) = server.recv_from(&mut query).await.unwrap();
                let question = parse_dns_query(&query[..length]).unwrap();
                let reply = build_dns_response(&question, rcode, Vec::new());
                server.send_to(&reply, peer).await.unwrap();
            });
            let runtime = NativeCoreRuntime::compile_with_egress(
                &direct_profile(),
                crate::NativeCoreEgressConfig {
                    dns_servers: vec![server_addr],
                    ..Default::default()
                },
            );
            let query = dns_query(0x1234, "rcode.test", DNS_TYPE_A);
            let reply = timeout(
                Duration::from_secs(1),
                resolve_dns_query_payload(&runtime, &query, None, None),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&reply[..2], &query[..2]);
            assert_eq!(u16::from(reply[3] & 0x0f), rcode);
            assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0);
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn direct_dns_transport_failure_returns_servfail_within_the_query_budget() {
        use tokio::net::UdpSocket;
        for malformed in [false, true] {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let mut query = [0; 512];
                let (_, peer) = server.recv_from(&mut query).await.unwrap();
                if malformed {
                    server.send_to(&query[..2], peer).await.unwrap();
                }
                // Keep the resolver socket open so the silent case is an
                // actual dropped response rather than an ICMP port refusal.
                std::future::pending::<()>().await;
                drop(server);
            });
            let runtime = NativeCoreRuntime::compile_with_egress(
                &direct_profile(),
                crate::NativeCoreEgressConfig {
                    dns_servers: vec![server_addr],
                    ..Default::default()
                },
            );
            let query = dns_query(0x4321, "failed.test", DNS_TYPE_A);
            let reply = timeout(
                Duration::from_secs(3),
                resolve_dns_query_payload(&runtime, &query, None, None),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(reply[3] & 0x0f, 2);
            assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0);
            task.abort();
        }
    }

    #[tokio::test]
    async fn system_resolver_answers_do_not_invent_an_upstream_ttl() {
        let runtime = NativeCoreRuntime::compile(&direct_profile());
        // A numeric name: the system resolver answers it without a network.
        let query = dns_query(0x1234, "127.0.0.1", DNS_TYPE_A);
        let response = resolve_dns_query_payload(&runtime, &query, None, None)
            .await
            .unwrap();
        assert_eq!(first_a_answer(&response), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(first_answer_ttl(&response), Some(0));
    }

    fn mapped_profile() -> RuntimeProfile {
        let mut profile = proxy_profile();
        profile.dns.hosts = vec![crate::dns::config::DnsHost {
            pattern: "+.nas.home".parse().unwrap(),
            addresses: vec!["192.168.1.10".parse().unwrap()],
        }];
        profile
    }

    #[tokio::test]
    async fn a_name_the_hosts_map_answers_its_addresses_ahead_of_fake_ips() {
        let runtime = NativeCoreRuntime::compile(&mapped_profile());
        let query = dns_query(0x1234, "files.nas.home", DNS_TYPE_A);
        let response = resolve_dns_query_payload(&runtime, &query, None, None)
            .await
            .unwrap();
        assert_eq!(
            first_a_answer(&response),
            Some(Ipv4Addr::new(192, 168, 1, 10))
        );
        assert_eq!(first_answer_ttl(&response), Some(HOSTS_TTL_SECONDS));
        // No IPv6 address in the mapping, and no service bindings: empty
        // answers, which no upstream gave.
        for qtype in [DNS_TYPE_AAAA, DNS_TYPE_HTTPS] {
            let query = dns_query(0x1234, "files.nas.home", qtype);
            let plan = plan_dns_query(&runtime, &query, None, None, DnsQueryTransport::Udp)
                .expect("the query plans");
            let DnsQueryPlan::Answered(response) = plan else {
                panic!("answered on the spot for type {qtype}");
            };
            assert_eq!(response[3] & 0x0f, 0, "NOERROR");
            assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        }
    }

    #[tokio::test]
    async fn without_use_hosts_the_apps_get_fake_ips_and_the_core_still_maps_the_name() {
        let mut profile = mapped_profile();
        profile.dns.use_hosts = false;
        let runtime = NativeCoreRuntime::compile(&profile);
        let query = dns_query(0x1234, "nas.home", DNS_TYPE_A);
        let response = resolve_dns_query_payload(&runtime, &query, None, None)
            .await
            .unwrap();
        let fake = first_a_answer(&response).expect("an A answer");
        assert!(matches!(fake.octets(), [198, 18 | 19, _, _]));
        let target = crate::target::ConnectTarget {
            host: "nas.home".into(),
            port: 445,
        };
        let resolved = runtime
            .dns_service()
            .resolve_target(
                &target,
                crate::dns::service::QueryPurpose::DirectTarget,
                Default::default(),
            )
            .await
            .expect("the mapping resolves it without a server");
        assert_eq!(resolved.authority(), "192.168.1.10:445");
        assert_eq!(
            runtime
                .egress()
                .hosts_target(&target)
                .map(|target| target.authority()),
            Some("192.168.1.10:445".into()),
            "a proxy is handed the mapped address"
        );
    }

    #[tokio::test]
    async fn localhost_names_answer_loopback_without_an_upstream() {
        let runtime = NativeCoreRuntime::compile(&proxy_profile());
        for name in ["localhost", "LocalHost", "app.localhost"] {
            let query = dns_query(0x1234, name, DNS_TYPE_A);
            let response = resolve_dns_query_payload(&runtime, &query, None, None)
                .await
                .unwrap();
            assert_eq!(
                first_a_answer(&response),
                Some(Ipv4Addr::LOCALHOST),
                "{name}"
            );
        }
        let query = dns_query(0x1234, "localhost", DNS_TYPE_TXT);
        let response = resolve_dns_query_payload(&runtime, &query, None, None)
            .await
            .unwrap();
        assert_eq!(response[3] & 0x0f, 0, "NOERROR");
        assert_eq!(
            u16::from_be_bytes([response[6], response[7]]),
            0,
            "no records"
        );
        assert!(is_localhost_name("Localhost."));
        assert!(is_localhost_name(" app.LOCALHOST "));
        assert!(!is_localhost_name("localhost.example.com"));
        assert!(!is_localhost_name("notlocalhost"));
        assert!(!is_localhost_name("host"));
        assert!(!is_localhost_name(""));
    }

    fn direct_profile() -> RuntimeProfile {
        let mut profile = proxy_profile();
        profile.rules = profile
            .rules
            .iter()
            .map(|rule| RouteRule {
                outbound: "DIRECT",
                ..rule
            })
            .collect();
        profile.dns = Default::default();
        profile
    }

    #[test]
    fn oversized_answer_set_truncates_with_tc_bit() {
        let query = dns_query(0x1234, "example.com", DNS_TYPE_A);
        let question = parse_dns_query(&query).expect("query parses");
        // 100 A records (~16 bytes each) far exceed the 512-byte UDP ceiling.
        let answers = (0..100)
            .map(|index| DnsAnswer {
                qtype: DNS_TYPE_A,
                qclass: DNS_CLASS_IN,
                ttl: 60,
                rdata: vec![10, 0, 0, index as u8],
            })
            .collect::<Vec<_>>();

        let response = build_dns_response(&question, DNS_RCODE_NOERROR, answers);

        assert!(response.len() <= DNS_UDP_MAX_RESPONSE_BYTES);
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_ne!(flags & DNS_RESPONSE_FLAG_TC, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    fn proxy_profile() -> RuntimeProfile {
        RuntimeProfile {
            dns: crate::dns::config::RuntimeDnsConfig {
                enabled: true,
                enhanced_mode: crate::dns::config::DnsMode::FakeIp,
                ..Default::default()
            },
            rule_sets: Vec::new(),
            geodata: Default::default(),
            id: "dns-proxy-profile".into(),
            name: "dns-proxy-profile".into(),
            traffic_policy_mode: crate::profile::TrafficPolicyMode::Rule,
            global_outbound: None,
            proxies: vec![ProxyNode {
                id: "proxy-http".into(),
                name: "Proxy".into(),
                protocol: ProxyProtocol::Http,
                server: Some("127.0.0.1".into()),
                port: Some(18080),
                options: serde_json::json!({}),
            }],
            groups: Vec::new(),
            rules: vec![RouteRule {
                kind: RuleKind::Match,
                payload: None,
                outbound: "Proxy",
                no_resolve: false,
            }]
            .into(),
        }
    }

    fn dns_query(id: u16, domain: &str, qtype: u16) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&id.to_be_bytes());
        query.extend_from_slice(&0x0100_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        query
    }

    fn first_answer_ttl(response: &[u8]) -> Option<u32> {
        if u16::from_be_bytes([response[6], response[7]]) == 0 {
            return None;
        }
        let mut offset = 12;
        while response.get(offset).copied()? != 0 {
            offset += usize::from(response[offset]) + 1;
        }
        offset += 1 + 4;
        let bytes = response.get(offset + 6..offset + 10)?;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }

    fn first_a_answer(response: &[u8]) -> Option<Ipv4Addr> {
        let answer_count = u16::from_be_bytes([response[6], response[7]]);
        if answer_count == 0 {
            return None;
        }
        let mut offset = 12;
        while response.get(offset).copied()? != 0 {
            offset += response[offset] as usize + 1;
        }
        offset += 1 + 4;
        if response.get(offset..offset + 16)?.first().copied()? != 0xc0 {
            return None;
        }
        let rdata_len = u16::from_be_bytes([response[offset + 10], response[offset + 11]]) as usize;
        if rdata_len != 4 {
            return None;
        }
        Some(Ipv4Addr::new(
            response[offset + 12],
            response[offset + 13],
            response[offset + 14],
            response[offset + 15],
        ))
    }

    fn first_aaaa_answer(response: &[u8]) -> Option<Ipv6Addr> {
        let answer_count = u16::from_be_bytes([response[6], response[7]]);
        if answer_count == 0 {
            return None;
        }
        let mut offset = 12;
        while response.get(offset).copied()? != 0 {
            offset += response[offset] as usize + 1;
        }
        offset += 1 + 4;
        if response.get(offset..offset + 28)?.first().copied()? != 0xc0 {
            return None;
        }
        let rdata_len = u16::from_be_bytes([response[offset + 10], response[offset + 11]]) as usize;
        if rdata_len != 16 {
            return None;
        }
        Some(Ipv6Addr::from(
            <[u8; 16]>::try_from(&response[offset + 12..offset + 28]).ok()?,
        ))
    }

    #[test]
    fn fake_allocation_is_stable_across_store_instances() {
        // Home slots are deterministic. These non-colliding names receive
        // the same addresses in fresh stores despite different query order;
        // collision resolution does not promise cross-session identity.
        let first = FakeDnsStore::default();
        let warmup = first.allocate_ipv4("warmup-a.example").expect("allocate");
        let target = first.allocate_ipv4("fanyi.example").expect("allocate");
        assert_ne!(warmup, target);

        let second = FakeDnsStore::default();
        second.allocate_ipv4("other-b.example").expect("allocate");
        second.allocate_ipv4("other-c.example").expect("allocate");
        assert_eq!(
            second.allocate_ipv4("fanyi.example").expect("allocate"),
            target
        );
        assert_eq!(
            first.allocate_ipv4("fanyi.example").expect("allocate"),
            target,
            "repeated allocation stays idempotent"
        );
        assert_eq!(
            first.allocate_ipv6("fanyi.example").expect("allocate v6"),
            project_ipv4_to_ipv6(target)
        );
        assert_eq!(first.len(), 2);
    }
}
