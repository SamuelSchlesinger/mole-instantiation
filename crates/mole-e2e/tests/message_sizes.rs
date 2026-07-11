//! Measure the real on-the-wire sizes of MoLE messages: the raw wire bytes
//! and the base64url header values they become. Run with `--nocapture`.

use anonymous_credit_tokens::{Params as ActParams, PreIssuance, PrivateKey};
use ihat::anchor::AnchorSecretKey;
use ihat::client::ClientNeedsSignature;
use ihat::{Params as IhatParams, WireFormat};
use mole_core::http::b64_encode;
use mole_core::messages::{
    ActIssuanceRequest, ActPresentationAndUpdate, CredentialPresentation, CredentialRequest,
    IhatPresentation,
};
use mole_core::wire::Wire;
use mole_core::{credential_type, endorsement_type};
use rand_core::{OsRng, RngCore};

#[test]
fn print_message_sizes() {
    let pp = IhatParams::standard();

    for n_anchors in [4usize, 16, 32] {
        let anchors: Vec<AnchorSecretKey> = (0..n_anchors)
            .map(|_| AnchorSecretKey::random(&mut OsRng))
            .collect();
        let accepted: Vec<_> = anchors.iter().map(|k| k.public_key(&pp)).collect();

        let mut nf = [0u8; 32];
        OsRng.fill_bytes(&mut nf);
        let (req, client) =
            ClientNeedsSignature::request(nf.to_vec(), b"epoch-1".to_vec(), &mut OsRng);
        let (sig, anchor) = req.sign(&pp, &anchors[0], &mut OsRng);
        let (proof_req, client) = client.request_proof(&pp, anchors[0].public_key(&pp), sig);
        let proof = anchor.prove(proof_req);
        let issued = client.finalize(&pp, proof).unwrap();
        let presentation = issued.show(&accepted, 0, b"binding", &mut OsRng);

        let act_params = ActParams::from_domain_separator(b"size-check");
        let _act_key = PrivateKey::random(OsRng);
        let pre = PreIssuance::random(OsRng);
        let act_request = pre.request(&act_params, OsRng);

        let credential_request = CredentialRequest {
            endorsement_type: endorsement_type::IHAT,
            endorsement_presentation: IhatPresentation {
                bytes: presentation.to_bytes().unwrap(),
            }
            .to_bytes(),
            credential_type: credential_type::ACT,
            issuance_request: ActIssuanceRequest {
                truncated_key_id: 0,
                request: act_request.to_bytes(),
            }
            .to_bytes(),
        }
        .to_bytes();
        println!(
            "CredentialRequest (redeem+issue), {n_anchors} anchors: {} bytes raw, {} bytes base64url",
            credential_request.len(),
            b64_encode(&credential_request).len()
        );
    }

    // A presentation: the ACT spend proof dominates.
    let act_params = ActParams::from_domain_separator(b"size-check");
    let act_key = PrivateKey::random(OsRng);
    let pre = PreIssuance::random(OsRng);
    let act_request = pre.request(&act_params, OsRng);
    let ctx = mole_core::act::request_context_scalar(b"policy", b"epoch-1");
    let response = act_key
        .issue(&act_params, &act_request, 10, ctx, OsRng)
        .unwrap();
    let token = pre
        .to_credit_token(&act_params, act_key.public(), &act_request, &response, ctx)
        .unwrap();
    let (spend, _pre_refund) = token.prove_spend(&act_params, 1, 0, OsRng).unwrap();

    let presentation = CredentialPresentation {
        credential_type: credential_type::ACT,
        presentation_and_update: ActPresentationAndUpdate {
            challenge_digest: [0; 32],
            key_id: [0; 32],
            spend_proof: spend.to_bytes(),
        }
        .to_bytes(),
    }
    .to_bytes();
    println!(
        "ACT SpendProof alone: {} bytes raw",
        spend.to_bytes().len()
    );
    println!(
        "CredentialPresentation (present+update): {} bytes raw, {} bytes base64url in the Authorization header",
        presentation.len(),
        b64_encode(&presentation).len()
    );
    println!(
        "IssuanceResponse header value: {} bytes base64url",
        b64_encode(&response.to_bytes()).len()
    );
    let refund = act_key.refund(&act_params, &spend, 0, OsRng).unwrap();
    println!(
        "Refund (update) header value: {} bytes base64url",
        b64_encode(&refund.to_bytes()).len()
    );
}
