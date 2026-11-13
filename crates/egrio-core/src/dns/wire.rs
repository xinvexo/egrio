//! DNS message semantics shared by physical and proxied transports. Hickory
//! owns wire encoding, compression and typed RDATA; this module only enforces
//! the transaction, address-selection and cache-lifetime contracts.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

const MAX_MESSAGE_BYTES: usize = u16::MAX as usize;

pub(crate) fn query(host: &str, qtype: RecordType) -> Result<Message, String> {
    if host.is_empty() {
        return Err("DNS query name is empty".into());
    }
    let mut name =
        Name::from_str_relaxed(host).map_err(|error| format!("invalid DNS query name: {error}"))?;
    name.set_fqdn(true);
    let mut request = Message::new();
    request
        .set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(Query::query(name, qtype));
    Ok(request)
}

pub(crate) fn decode(bytes: &[u8]) -> Result<Message, String> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err("DNS message exceeds the 65535-byte wire limit".into());
    }
    let mut message =
        Message::from_vec(bytes).map_err(|error| format!("invalid DNS message: {error}"))?;
    age_ttls(&mut message, Duration::ZERO);
    Ok(message)
}

pub(crate) fn encode(message: &Message) -> Result<Vec<u8>, String> {
    let encoded = message
        .to_vec()
        .map_err(|error| format!("cannot encode DNS message: {error}"))?;
    if encoded.len() > MAX_MESSAGE_BYTES {
        return Err("DNS message exceeds the 65535-byte wire limit".into());
    }
    Ok(encoded)
}

pub(crate) fn validate_request(request: &Message) -> Result<(), String> {
    if request.message_type() != MessageType::Query || request.op_code() != OpCode::Query {
        return Err("DNS request must be a standard query".into());
    }
    if request.queries().len() != 1 {
        return Err("DNS request must contain exactly one question".into());
    }
    Ok(())
}

pub(crate) fn validate_response(request: &Message, answer: &Message) -> Result<(), String> {
    validate_request(request)?;
    if answer.message_type() != MessageType::Response || answer.op_code() != request.op_code() {
        return Err("DNS response has invalid transaction flags".into());
    }
    if answer.id() != request.id() {
        return Err("DNS response ID mismatch".into());
    }
    // Name equality in Hickory is DNS case-insensitive, while class/type are
    // exact. RCODE and TC are outcomes for the caller, not malformed replies.
    // Format/refusal failures may contain only a response header. A matched
    // peer/ID/opcode still carries an RCODE; never turn that into a timeout.
    let header_only_error =
        answer.queries().is_empty() && answer.response_code() != ResponseCode::NoError;
    if !header_only_error && answer.queries() != request.queries() {
        return Err("DNS response question mismatch".into());
    }
    Ok(())
}

pub(crate) fn response(request: &Message, rcode: ResponseCode) -> Message {
    let mut answer = Message::new();
    answer
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_op_code(request.op_code())
        .set_recursion_desired(request.recursion_desired())
        .set_recursion_available(true)
        .set_checking_disabled(request.checking_disabled())
        .set_response_code(rcode)
        .add_queries(request.queries().iter().cloned());
    if let Some(request_edns) = request.extensions() {
        let mut edns = Edns::new();
        edns.set_max_payload(request_edns.max_payload())
            .set_dnssec_ok(request_edns.flags().dnssec_ok);
        answer.set_edns(edns);
    }
    answer
}

fn terminal_owner(message: &Message) -> Result<Name, String> {
    let question = message.query().ok_or("DNS response has no question")?;
    let mut owner = question.name().to_lowercase();
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(owner.clone()) {
            return Err("DNS CNAME loop".into());
        }
        let mut next = None;
        for record in message.answers() {
            if record.name() != &owner || record.dns_class() != question.query_class() {
                continue;
            }
            if let RData::CNAME(alias) = record.data() {
                let alias = alias.0.to_lowercase();
                if next.as_ref().is_some_and(|previous| previous != &alias) {
                    return Err("DNS owner has conflicting CNAME targets".into());
                }
                next = Some(alias);
            }
        }
        match next {
            Some(alias) => owner = alias,
            None => return Ok(owner),
        }
    }
}

pub(crate) fn addresses(message: &Message) -> Result<Vec<IpAddr>, String> {
    if message.message_type() != MessageType::Response || message.queries().len() != 1 {
        return Err("DNS address response must contain one echoed question".into());
    }
    if message.truncated() {
        return Err("DNS address response is truncated".into());
    }
    if message.response_code() != ResponseCode::NoError {
        return Err(format!("DNS response returned {}", message.response_code()));
    }
    let question = message.query().expect("one DNS question");
    if question.query_class() != DNSClass::IN
        || !matches!(question.query_type(), RecordType::A | RecordType::AAAA)
    {
        return Ok(Vec::new());
    }
    let owner = terminal_owner(message)?;
    let mut addresses = Vec::new();
    for record in message.answers() {
        if record.name() != &owner
            || record.dns_class() != question.query_class()
            || record.record_type() != question.query_type()
        {
            continue;
        }
        let address = match record.data() {
            RData::A(value) => IpAddr::V4(value.0),
            RData::AAAA(value) => IpAddr::V6(value.0),
            _ => continue,
        };
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    Ok(addresses)
}

fn valid_ttl(ttl: u32) -> u32 {
    // RFC 2181 section 8: the high bit is not part of a valid TTL.
    if ttl & 0x8000_0000 == 0 {
        ttl
    } else {
        0
    }
}

/// The longest a negative answer is kept, whatever its SOA allows: long
/// enough for the SOA lifetimes resolvers hand out (68-398 s from 223.5.5.5
/// for names without AAAA records), short enough that a name that gains
/// records is seen within a quarter of an hour. RFC 2308 section 5 leaves the
/// bound to the cache.
const MAX_NEGATIVE_TTL: u32 = 900;

/// How long a negative answer may be cached (RFC 2308): a name that does not
/// exist (NXDOMAIN), or one with no record of the asked type at the end of
/// its CNAME chain (NODATA), for the lesser of the authority SOA's TTL and
/// its MINIMUM field (section 5), capped at [`MAX_NEGATIVE_TTL`] and bounded
/// by any CNAME TTL on the way. An answer without an SOA is not cached
/// (section 5), and neither is any other failure.
pub(crate) fn negative_ttl(message: &Message) -> Option<Duration> {
    if message.message_type() != MessageType::Response
        || message.op_code() != OpCode::Query
        || message.truncated()
        || message.queries().len() != 1
        || !message.signature().is_empty()
    {
        return None;
    }
    let question = message.query()?;
    match message.response_code() {
        ResponseCode::NXDomain => {}
        ResponseCode::NoError => {
            let owner = terminal_owner(message).ok()?;
            if message.answers().iter().any(|record| {
                record.name() == &owner
                    && record.dns_class() == question.query_class()
                    && (record.record_type() == question.query_type()
                        || question.query_type() == RecordType::ANY)
            }) {
                return None;
            }
        }
        _ => return None,
    }
    let soa = message
        .name_servers()
        .iter()
        .find_map(|record| match record.data() {
            RData::SOA(soa) => Some(valid_ttl(record.ttl()).min(soa.minimum())),
            _ => None,
        })?;
    let ttl = message
        .answers()
        .iter()
        .map(|record| valid_ttl(record.ttl()))
        .fold(soa.min(MAX_NEGATIVE_TTL), u32::min);
    (ttl > 0).then(|| Duration::from_secs(u64::from(ttl)))
}

pub(crate) fn positive_ttl(message: &Message) -> Option<Duration> {
    if message.message_type() != MessageType::Response
        || message.op_code() != OpCode::Query
        || message.response_code() != ResponseCode::NoError
        || message.truncated()
        || message.queries().len() != 1
        || !message.signature().is_empty()
    {
        return None;
    }
    let question = message.query()?;
    let owner = if question.query_type() == RecordType::CNAME {
        question.name().clone()
    } else {
        terminal_owner(message).ok()?
    };
    // A CNAME chain ending in NODATA is a negative answer, not a positive A
    // cache entry. Generic types (TXT/SRV/HTTPS/etc.) retain their full RDATA.
    if !message.answers().iter().any(|record| {
        record.name() == &owner
            && record.dns_class() == question.query_class()
            && (record.record_type() == question.query_type()
                || question.query_type() == RecordType::ANY)
    }) {
        return None;
    }
    let ttl = message
        .all_sections()
        .filter(|record| record.record_type() != RecordType::OPT)
        .map(|record| valid_ttl(record.ttl()))
        .min()?;
    (ttl > 0).then(|| Duration::from_secs(u64::from(ttl)))
}

pub(crate) fn age_ttls(message: &mut Message, age: Duration) {
    // Floor the remaining lifetime, not the elapsed duration: re-serving a
    // fractional second old answer must not extend its original expiration.
    let elapsed = age
        .as_secs()
        .saturating_add(u64::from(age.subsec_nanos() != 0));
    let elapsed = u32::try_from(elapsed).unwrap_or(u32::MAX);
    fn age_records(records: &mut [Record], elapsed: u32) {
        for record in records {
            if record.record_type() != RecordType::OPT {
                record.set_ttl(valid_ttl(record.ttl()).saturating_sub(elapsed));
            }
        }
    }
    age_records(message.answers_mut(), elapsed);
    age_records(message.name_servers_mut(), elapsed);
    age_records(message.additionals_mut(), elapsed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, SOA, TXT};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn record(owner: &str, ttl: u32, data: RData) -> Record {
        Record::from_rdata(Name::from_ascii(owner).unwrap(), ttl, data)
    }

    #[test]
    fn full_messages_round_trip_with_non_address_records_and_rcodes() {
        let request = query("example.test.", RecordType::TXT).unwrap();
        let mut answer = response(&request, ResponseCode::NoError);
        answer.add_answer(record(
            "example.test.",
            60,
            RData::TXT(TXT::new(vec!["v=example value".into()])),
        ));
        answer.add_name_server(record(
            "test.",
            30,
            RData::NS(NS(Name::from_ascii("ns.test.").unwrap())),
        ));
        answer.add_additional(record("ns.test.", 20, RData::A(A(Ipv4Addr::LOCALHOST))));
        let decoded = decode(&encode(&answer).unwrap()).unwrap();
        validate_response(&request, &decoded).unwrap();
        assert_eq!(decoded.answers(), answer.answers());
        assert_eq!(decoded.name_servers(), answer.name_servers());
        assert_eq!(decoded.additionals(), answer.additionals());
        assert_eq!(positive_ttl(&decoded), Some(Duration::from_secs(20)));
        let negative = response(&request, ResponseCode::NXDomain);
        let negative = decode(&encode(&negative).unwrap()).unwrap();
        validate_response(&request, &negative).unwrap();
        assert_eq!(negative.response_code(), ResponseCode::NXDomain);
        assert!(positive_ttl(&negative).is_none());
    }

    #[test]
    fn response_validation_checks_id_opcode_question_but_preserves_wire_outcomes() {
        let request = query("example.test.", RecordType::A).unwrap();
        let mut answer = response(&request, ResponseCode::ServFail);
        validate_response(&request, &answer).unwrap();
        answer.set_truncated(true);
        validate_response(&request, &answer).unwrap();
        answer.set_id(request.id().wrapping_add(1));
        assert!(validate_response(&request, &answer)
            .unwrap_err()
            .contains("ID"));
        answer.set_id(request.id());
        answer.queries_mut()[0].set_query_type(RecordType::AAAA);
        assert!(validate_response(&request, &answer)
            .unwrap_err()
            .contains("question"));
        let mut case = response(&request, ResponseCode::NoError);
        case.queries_mut()[0].set_name(Name::from_ascii("EXAMPLE.TEST.").unwrap());
        validate_response(&request, &case).unwrap();
        case.set_op_code(OpCode::Status);
        assert!(validate_response(&request, &case).is_err());
    }

    #[test]
    fn header_only_error_responses_preserve_rcode_but_success_requires_the_question() {
        let request = query("failure.test", RecordType::A).unwrap();
        for rcode in [
            ResponseCode::FormErr,
            ResponseCode::NXDomain,
            ResponseCode::ServFail,
            ResponseCode::Refused,
        ] {
            let mut error = response(&request, rcode);
            error.queries_mut().clear();
            validate_response(&request, &error).unwrap();
            let decoded = decode(&encode(&error).unwrap()).unwrap();
            assert_eq!(decoded.response_code(), rcode);
            validate_response(&request, &decoded).unwrap();
            assert!(positive_ttl(&decoded).is_none());
        }
        let mut malformed = response(&request, ResponseCode::NoError);
        malformed.queries_mut().clear();
        assert!(validate_response(&request, &malformed).is_err());
    }

    #[test]
    fn addresses_follow_only_the_questions_reachable_cname_chain_and_family() {
        let request = query("alias.test.", RecordType::A).unwrap();
        let mut answer = response(&request, ResponseCode::NoError);
        answer.add_answer(record(
            "alias.test.",
            10,
            RData::CNAME(CNAME(Name::from_ascii("target.test.").unwrap())),
        ));
        answer.add_answer(record(
            "unrelated.test.",
            60,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
        ));
        answer.add_answer(record(
            "target.test.",
            30,
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        ));
        answer.add_answer(record(
            "target.test.",
            30,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        assert_eq!(
            addresses(&answer).unwrap(),
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(positive_ttl(&answer), Some(Duration::from_secs(10)));
        answer.add_answer(record(
            "target.test.",
            30,
            RData::CNAME(CNAME(Name::from_ascii("alias.test.").unwrap())),
        ));
        assert!(addresses(&answer).unwrap_err().contains("CNAME loop"));
        assert!(positive_ttl(&answer).is_none());
    }

    fn soa(ttl: u32, minimum: u32) -> Record {
        record(
            "test.",
            ttl,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.test.").unwrap(),
                Name::from_ascii("admin.test.").unwrap(),
                1,
                3600,
                600,
                86400,
                minimum,
            )),
        )
    }

    #[test]
    fn a_negative_answer_lives_by_its_soa_and_only_with_one() {
        let request = query("v4only.test.", RecordType::AAAA).unwrap();
        // NODATA: the name exists, with no AAAA record.
        let mut nodata = response(&request, ResponseCode::NoError);
        nodata.add_name_server(soa(398, 3600));
        assert_eq!(negative_ttl(&nodata), Some(Duration::from_secs(398)));
        assert!(positive_ttl(&nodata).is_none());
        // The lesser of the SOA's TTL and its MINIMUM, then the cap.
        let mut nxdomain = response(&request, ResponseCode::NXDomain);
        nxdomain.add_name_server(soa(600, 180));
        assert_eq!(negative_ttl(&nxdomain), Some(Duration::from_secs(180)));
        let mut long = response(&request, ResponseCode::NXDomain);
        long.add_name_server(soa(86400, 86400));
        assert_eq!(
            negative_ttl(&long),
            Some(Duration::from_secs(u64::from(MAX_NEGATIVE_TTL)))
        );
        // A CNAME chain ending in NODATA lives no longer than its CNAME.
        let mut chained = response(&request, ResponseCode::NoError);
        chained.add_answer(record(
            "v4only.test.",
            30,
            RData::CNAME(CNAME(Name::from_ascii("target.test.").unwrap())),
        ));
        chained.add_name_server(soa(398, 3600));
        assert_eq!(negative_ttl(&chained), Some(Duration::from_secs(30)));
        // Without an SOA, an answer, or another failure, nothing is cached.
        assert!(negative_ttl(&response(&request, ResponseCode::NXDomain)).is_none());
        let mut answered = response(&request, ResponseCode::NoError);
        answered.add_answer(record(
            "v4only.test.",
            60,
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        ));
        answered.add_name_server(soa(398, 3600));
        assert!(negative_ttl(&answered).is_none());
        let mut failed = response(&request, ResponseCode::ServFail);
        failed.add_name_server(soa(398, 3600));
        assert!(negative_ttl(&failed).is_none());
        // The SOA survives the wire.
        let decoded = decode(&encode(&nodata).unwrap()).unwrap();
        assert_eq!(negative_ttl(&decoded), Some(Duration::from_secs(398)));
    }

    #[test]
    fn ttl_aging_floors_remaining_lifetime_and_never_ages_edns_flags() {
        let mut request = query("example.test.", RecordType::A).unwrap();
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true).set_max_payload(1232);
        request.set_edns(edns);
        let mut answer = response(&request, ResponseCode::NoError);
        answer.add_answer(record(
            "example.test.",
            60,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        ));
        age_ttls(&mut answer, Duration::from_millis(1500));
        assert_eq!(answer.answers()[0].ttl(), 58);
        assert!(answer.extensions().as_ref().unwrap().flags().dnssec_ok);
        assert_eq!(answer.extensions().as_ref().unwrap().max_payload(), 1232);
        answer.answers_mut()[0].set_ttl(0x8000_0001);
        assert!(positive_ttl(&answer).is_none());
        age_ttls(&mut answer, Duration::ZERO);
        assert_eq!(answer.answers()[0].ttl(), 0);
    }

    #[test]
    fn query_names_use_dns_label_rules_without_imposing_hostname_idna_restrictions() {
        for host in ["service_label.test", "_service._tcp.test", "例子.test"] {
            let request = query(host, RecordType::TXT).unwrap();
            let decoded = decode(&encode(&request).unwrap()).unwrap();
            assert_eq!(decoded.queries(), request.queries());
            validate_response(&request, &response(&decoded, ResponseCode::NoError)).unwrap();
        }
    }

    #[test]
    fn hickory_rejects_truncated_records_and_cyclic_compression() {
        let request = query("example.test.", RecordType::A).unwrap();
        let mut bytes = encode(&request).unwrap();
        bytes.truncate(bytes.len() - 1);
        assert!(decode(&bytes).is_err());
        let looped = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1];
        assert!(decode(&looped).is_err());
    }
}
