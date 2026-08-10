// ============================================================================
// Door A — Attestation Binding + Delivery Identity Model (v1.3.4)
// ============================================================================
// Tool:    Dafny 4.9.1 (Z3 4.12.1)
// Command: dafny verify --function-syntax:4 binding_v1_3_4.dfy
//
// Part I  (v1.3.3, retained): Y1/Y1b attestation binding under AT-8 / TR-10.
// Part II (NEW in v1.3.4):    Y3 delivery identity — proves that DS-1's
//         idempotency key must be derived from ACTION IDENTITY, not from
//         attestation_id, or the DS-3 re-drive path admits a duplicate
//         execution; and that the corrected key preserves authorization
//         freshness (re-drive still consumes a NEW attestation).
//
// Additions vs v1.3.3 Part I:
//   * HonestPathAccepted           — non-vacuity witness for Verify_v133.
//   * Y1_AttackBlocked_Generalized — attacker has observed ARBITRARILY MANY
//                                    legitimate signatures, not exactly one.
// ============================================================================

module ACP_AttestationBinding {

  datatype Preimage =
    | PProposal(fields: seq<int>)
    | PObject(phash: Hash, bhash: Hash, epoch: int,
              risk: int, nonce: int, expires: int, operator: int)

  type Hash = int

  function {:axiom} H(p: Preimage): Hash
  lemma {:axiom} H_Injective(a: Preimage, b: Preimage)
    ensures H(a) == H(b) ==> a == b

  type Key = int
  ghost predicate Signed(key: Key, bytes: Hash)

  // AT-1 object. `operator` added in v1.3.4 (closes Y4: the Executor takes
  // operator from the VERIFIED object, never from the receipt body).
  datatype AttObject = AttObject(
    proposal_hash: Hash,
    bundle_hash: Hash,
    epoch: int,
    floor_risk: int,
    att_nonce: int,
    expires: int,
    operator: int)

  function ObjectPreimage(o: AttObject): Preimage {
    PObject(o.proposal_hash, o.bundle_hash, o.epoch, o.floor_risk,
            o.att_nonce, o.expires, o.operator)
  }

  function AttestationId(o: AttObject): Hash { H(ObjectPreimage(o)) }

  datatype AttEntry_v132 = AttEntry_v132(
    transmitted_id: Hash, attester: Key, sig_over: Hash)

  datatype AttEntry_v133 = AttEntry_v133(obj: AttObject, attester: Key)

  // ---------------- v1.3.2 check (the defect, mechanized) ----------------
  ghost predicate Verify_v132(e: AttEntry_v132, executed_phash: Hash)
  { Signed(e.attester, e.sig_over) }

  lemma Y1_CurrentCheckAcceptsMisbinding(
      attester: Key, legit: AttObject, executed_phash: Hash)
    requires legit.proposal_hash != executed_phash
    requires Signed(attester, AttestationId(legit))
    ensures exists e: AttEntry_v132 ::
              Verify_v132(e, executed_phash)
              && e.sig_over == AttestationId(legit)
  {
    var e := AttEntry_v132(AttestationId(legit), attester, AttestationId(legit));
    assert Signed(attester, e.sig_over);
  }

  // ---------------- v1.3.3+ check (AT-8 / TR-10) ----------------
  ghost predicate Verify_v133(e: AttEntry_v133, executed_phash: Hash,
                              trusted_bhash: Hash, trusted_epoch: int,
                              recomputed_risk: int)
  {
    Signed(e.attester, AttestationId(e.obj))          // (i)
    && e.obj.proposal_hash == executed_phash           // (ii) THE BINDING
    && e.obj.bundle_hash == trusted_bhash              // (iii)
    && e.obj.epoch == trusted_epoch
    && e.obj.floor_risk == recomputed_risk
  }

  function LedgerId_v133(e: AttEntry_v133): Hash { AttestationId(e.obj) }

  lemma BindingSound(e: AttEntry_v133, executed_phash: Hash,
                     tb: Hash, te: int, rr: int)
    requires Verify_v133(e, executed_phash, tb, te, rr)
    ensures Signed(e.attester, AttestationId(e.obj))
    ensures e.obj.proposal_hash == executed_phash
  { }

  // NON-VACUITY (NEW v1.3.4). Verify_v133 is satisfiable, so the negative
  // results below are not true merely because nothing ever verifies.
  lemma HonestPathAccepted(attester: Key, o: AttObject)
    requires Signed(attester, AttestationId(o))
    ensures Verify_v133(AttEntry_v133(o, attester), o.proposal_hash,
                        o.bundle_hash, o.epoch, o.floor_risk)
  { }

  // GENERALIZED ATTACKER (NEW v1.3.4). Replaces the v1.3.3 premise that the
  // attester ever signed exactly one message. Here the attester has signed
  // arbitrarily many objects; the only hypothesis is that none of them binds
  // the executed proposal.
  lemma Y1_AttackBlocked_Generalized(
      attester: Key, executed_phash: Hash, tb: Hash, te: int, rr: int)
    requires forall bytes :: Signed(attester, bytes) ==>
               exists o: AttObject :: bytes == AttestationId(o)
                                      && o.proposal_hash != executed_phash
    ensures forall e: AttEntry_v133 ::
              e.attester == attester ==>
              !Verify_v133(e, executed_phash, tb, te, rr)
  {
    forall e: AttEntry_v133 | e.attester == attester
      ensures !Verify_v133(e, executed_phash, tb, te, rr)
    {
      if Verify_v133(e, executed_phash, tb, te, rr) {
        assert Signed(e.attester, AttestationId(e.obj));
        var o :| AttestationId(e.obj) == AttestationId(o)
                 && o.proposal_hash != executed_phash;
        H_Injective(ObjectPreimage(e.obj), ObjectPreimage(o));
        assert e.obj == o;
        assert e.obj.proposal_hash == executed_phash;
        assert false;
      }
    }
  }

  // ---- Y4 (NEW v1.3.4): operator is signature-covered. --------------------
  // Because `operator` is an AT-1 object field, a KMS cannot substitute a
  // different operator without changing the id the attester signed. This is
  // what makes step 7b's distinctness check and step 9's capability recheck
  // key on a verified value rather than a receipt-body claim.
  lemma Y4_OperatorTamperDetected(o1: AttObject, o2: AttObject)
    requires o1.operator != o2.operator
    ensures AttestationId(o1) != AttestationId(o2)
  {
    if AttestationId(o1) == AttestationId(o2) {
      H_Injective(ObjectPreimage(o1), ObjectPreimage(o2));
      assert o1 == o2;
      assert false;
    }
  }

  lemma Y1b_LedgerConsumesRealId(e: AttEntry_v133, executed_phash: Hash,
                                 tb: Hash, te: int, rr: int)
    requires Verify_v133(e, executed_phash, tb, te, rr)
    ensures LedgerId_v133(e) == AttestationId(e.obj)
    ensures Signed(e.attester, LedgerId_v133(e))
  { }

  // ==========================================================================
  // PART II — Y3: DELIVERY IDENTITY (NEW in v1.3.4)
  // ==========================================================================
  // DS-1 keys target idempotency on `attestation_id`. DS-3 re-drives an
  // `indeterminate` outcome "through a new attestation". A new attestation has
  // a new nonce, hence a new id, hence a NEW idempotency key — in exactly the
  // case where the original call may have SUCCEEDED and only its outcome was
  // lost. The target therefore cannot dedup, and the action doubles.
  //
  // Modelled: an Attempt is (authorizing object, action identity). The
  // idempotency key is a function of the attempt. A target dedups two attempts
  // iff their keys are equal. "Doubled execution" = two attempts of the SAME
  // action with DIFFERENT keys.
  // --------------------------------------------------------------------------

  // Stable identity of the action being driven: fixed at first authorization
  // and carried forward across re-drives (DS-6). Modelled as the first
  // receipt's nonce paired with the proposal hash.
  datatype ActionIdentity = ActionIdentity(proposal_hash: Hash, origin_nonce: int)

  datatype Attempt = Attempt(auth: AttObject, action: ActionIdentity)

  // v1.3.3 key (DS-1 as written): derived from the AUTHORIZATION.
  function Key_v133(a: Attempt): Hash { AttestationId(a.auth) }

  // v1.3.4 key (DS-6, proposed): derived from the ACTION IDENTITY.
  function Key_v134(a: Attempt): Hash
  { H(PProposal([a.action.proposal_hash, a.action.origin_nonce])) }

  ghost predicate SameAction(a: Attempt, b: Attempt) { a.action == b.action }
  ghost predicate Dedupped(k1: Hash, k2: Hash) { k1 == k2 }

  // A re-drive per DS-3: same action, but a FRESH attestation object (fresh
  // nonce ==> different object ==> different id). This is what DS-3 mandates.
  ghost predicate IsRedrive(orig: Attempt, re: Attempt)
  {
    SameAction(orig, re) && re.auth.att_nonce != orig.auth.att_nonce
  }

  // ---- NEGATIVE RESULT: the Y3 defect, mechanized. -------------------------
  // Under DS-1's key, a lawful DS-3 re-drive is NOT dedupped by the target.
  lemma Y3_RedriveDefeatsDedup(orig: Attempt, re: Attempt)
    requires IsRedrive(orig, re)
    ensures !Dedupped(Key_v133(orig), Key_v133(re))
  {
    if Dedupped(Key_v133(orig), Key_v133(re)) {
      // equal ids ==> equal objects (injectivity) ==> equal nonces
      H_Injective(ObjectPreimage(orig.auth), ObjectPreimage(re.auth));
      assert orig.auth == re.auth;
      assert orig.auth.att_nonce == re.auth.att_nonce;   // contradicts IsRedrive
      assert false;
    }
  }

  // ---- POSITIVE RESULT: DS-6 restores exactly-once across re-drives. -------
  lemma Y3_Fixed_RedriveIsDedupped(orig: Attempt, re: Attempt)
    requires IsRedrive(orig, re)
    ensures Dedupped(Key_v134(orig), Key_v134(re))
  { }

  // ---- The fix does NOT weaken authorization freshness. --------------------
  // A re-drive still carries a DISTINCT attestation object, so the Consumption
  // Ledger still consumes a fresh id (CL-3 / AT-5 intact). Key stability and
  // authorization freshness are independent properties.
  lemma Y3_Fixed_AuthorizationStillFresh(orig: Attempt, re: Attempt)
    requires IsRedrive(orig, re)
    ensures AttestationId(orig.auth) != AttestationId(re.auth)
    ensures Key_v134(orig) == Key_v134(re)
  {
    if AttestationId(orig.auth) == AttestationId(re.auth) {
      H_Injective(ObjectPreimage(orig.auth), ObjectPreimage(re.auth));
      assert false;
    }
  }

  // ---- Distinct actions never collide on the stable key. ------------------
  // Guards the obvious way to get DS-6 wrong: a key so coarse that two
  // different actions share it would suppress a LEGITIMATE second action.
  lemma Y3_Fixed_DistinctActionsDistinctKeys(a: Attempt, b: Attempt)
    requires a.action != b.action
    ensures Key_v134(a) != Key_v134(b)
  {
    if Key_v134(a) == Key_v134(b) {
      H_Injective(PProposal([a.action.proposal_hash, a.action.origin_nonce]),
                  PProposal([b.action.proposal_hash, b.action.origin_nonce]));
      assert [a.action.proposal_hash, a.action.origin_nonce]
          == [b.action.proposal_hash, b.action.origin_nonce];
      assert a.action.proposal_hash == b.action.proposal_hash;
      assert a.action.origin_nonce == b.action.origin_nonce;
      assert false;
    }
  }

  // ==========================================================================
  // PART III — Z3 / Z4: ORIGIN PINNING AND ENCODING UNIQUENESS (v1.3.5)
  // ==========================================================================
  // Z3. DS-6b (v1.3.4) required the Executor to verify that the claimed
  // `origin_nonce` is "recorded as consumed in the Consumption Ledger". That
  // is a MEMBERSHIP test: it proves the nonce is *a* consumed nonce, not *the*
  // origin nonce of this proposal. A compromised KMS substitutes any other
  // consumed nonce, the idempotency key changes, the target cannot dedup, and
  // the action doubles. RES-8 class, fourth recurrence, in the machinery the
  // Y3 fix introduced.
  // --------------------------------------------------------------------------

  // The ledger's origin binding: claimed atomically at FIRST receipt issuance
  // for a proposal, immutable thereafter. Modelled as a total map from the
  // proposal hash to the pinned origin nonce.
  datatype Ledger = Ledger(origin: map<Hash, int>, consumed: set<int>)

  // v1.3.4 key: origin taken from the RECEIPT (class T -- the defect).
  function Key_transmitted(phash: Hash, claimed_origin: int): Hash
  { H(PProposal([phash, claimed_origin])) }

  // v1.3.5 key: origin taken from the LEDGER (class R/B -- the fix).
  function Key_pinned(l: Ledger, phash: Hash): Hash
    requires phash in l.origin
  { H(PProposal([phash, l.origin[phash]])) }

  // The v1.3.4 check, modelled faithfully: membership only.
  ghost predicate OriginCheck_v134(l: Ledger, claimed_origin: int)
  { claimed_origin in l.consumed }

  // ---- NEGATIVE RESULT: Z3, mechanized. -----------------------------------
  // A claimed origin that passes the v1.3.4 membership check but is not the
  // pinned origin yields a DIFFERENT idempotency key. Dedup is defeated while
  // every stated check passes.
  lemma Z3_MembershipCheckDoesNotPinOrigin(
      l: Ledger, phash: Hash, claimed_origin: int)
    requires phash in l.origin
    requires OriginCheck_v134(l, claimed_origin)      // check passes
    requires claimed_origin != l.origin[phash]        // but it is the wrong one
    ensures Key_transmitted(phash, claimed_origin) != Key_pinned(l, phash)
  {
    if Key_transmitted(phash, claimed_origin) == Key_pinned(l, phash) {
      H_Injective(PProposal([phash, claimed_origin]),
                  PProposal([phash, l.origin[phash]]));
      assert [phash, claimed_origin] == [phash, l.origin[phash]];
      assert claimed_origin == l.origin[phash];
      assert false;
    }
  }

  // ---- POSITIVE RESULT: DS-6f pins the origin. ----------------------------
  // NOTE ON WHAT IS *NOT* PROVEN HERE. "The key is independent of what the
  // receipt claims" is true BY CONSTRUCTION: `claimed_origin` is not an
  // argument of `Key_pinned`. Stating it as a lemma would be a tautological
  // postcondition -- the proof-body honesty defect this document's own
  // mutation testing caught as X4 -- so it is asserted at the type level and
  // deliberately NOT dressed up as a theorem. What genuinely requires proof is
  // that pinning does not over-collapse; that is the lemma below.

  // Distinct proposals still get distinct keys under pinning (no over-collapse).
  lemma Z3_Fixed_DistinctProposalsDistinctKeys(l: Ledger, p1: Hash, p2: Hash)
    requires p1 in l.origin && p2 in l.origin
    requires p1 != p2
    requires l.origin[p1] == l.origin[p2]   // even on a nonce collision
    ensures Key_pinned(l, p1) != Key_pinned(l, p2)
  {
    if Key_pinned(l, p1) == Key_pinned(l, p2) {
      H_Injective(PProposal([p1, l.origin[p1]]), PProposal([p2, l.origin[p2]]));
      assert [p1, l.origin[p1]] == [p2, l.origin[p2]];
      assert p1 == p2;
      assert false;
    }
  }

  // --------------------------------------------------------------------------
  // Z4. AT-8a fixed the CANONICALIZER but not the SCHEMA. If the Attestation
  // Object admits an optional field, two encodings of one semantic object are
  // each canonical, hash to two ids, and claim two ledger slots -- T-14
  // attestation amplification reopens through the mechanism Y1b closed.
  // Modelled: an encoding choice parameter that must not exist.
  // --------------------------------------------------------------------------

  datatype Encoding = Omitted | ExplicitNull

  // An object whose encoding depends on a choice: two preimages, one meaning.
  function EncodeWithChoice(o: AttObject, c: Encoding): Preimage
  {
    match c
      case Omitted      => PProposal([o.proposal_hash, o.att_nonce, 0])
      case ExplicitNull => PProposal([o.proposal_hash, o.att_nonce, 1])
  }

  // ---- NEGATIVE RESULT: Z4, mechanized. -----------------------------------
  lemma Z4_OptionalFieldYieldsTwoIds(o: AttObject)
    ensures H(EncodeWithChoice(o, Omitted)) != H(EncodeWithChoice(o, ExplicitNull))
  {
    if H(EncodeWithChoice(o, Omitted)) == H(EncodeWithChoice(o, ExplicitNull)) {
      H_Injective(EncodeWithChoice(o, Omitted), EncodeWithChoice(o, ExplicitNull));
      assert [o.proposal_hash, o.att_nonce, 0] == [o.proposal_hash, o.att_nonce, 1];
      assert (0 as int) == (1 as int);
      assert false;
    }
  }
  // Reading: the two ids differ, so ONE attestation claims TWO ledger slots.
  // AT-8b (closed schema, all fields REQUIRED, no extensions) removes the
  // choice parameter entirely, which is why the fix is schema-level and cannot
  // be achieved by canonicalization rules alone.
}

// ============================================================================
// PART IV — DEFERRED RELEASE AND REVERSIBILITY (v1.3.7)
// ============================================================================
// Models §9.6 DR-9/DR-10/DR-11 and §8.3 RV-1/RV-3.
//
// SCOPE AND ITS LIMIT, STATED FIRST. DR-9 requires a human acknowledgement.
// Whether the acknowledging human READ the summary is outside any model, and
// nothing below claims otherwise: acknowledgement is an input, not a proof of
// attention. What IS mechanizable is structural, and that is what is proven --
// that no transmitted value can move the release mode, that an unclassified
// action cannot release silently, that the operator's own acknowledgement does
// not satisfy DR-9, and that the sampling draw is not grindable.
//
// METHODOLOGICAL NOTE (avoiding the X4 tautology trap). A previous revision of
// this artifact stated "the key is independent of the receipt" as a lemma when
// the claimed value was not an argument of the function -- true by typing, not
// by proof, and therefore worthless. Here the receipt and the task are kept as
// EXPLICIT PARAMETERS of the recomputing functions even though their bodies
// ignore the receipt. The independence lemmas therefore quantify over a real
// argument and constrain the function BODY. Removing the parameter would make
// the lemmas trivial; keeping it is what makes them evidence.
// ============================================================================

module ACP_DeferredRelease {

  datatype Reversibility = REVERSIBLE | IRREVERSIBLE
  datatype Mode = Silent | Confirmed

  type Task = int
  type Party = int

  datatype Bundle = Bundle(rev: map<Task, Reversibility>)
  datatype Receipt = Receipt(claimed_rev: Reversibility, claimed_task: Task)
  datatype Pending = Pending(operator: Party, confirmed: set<Party>)

  // ---------------- RV-1: fail-safe default ----------------
  function RevOf(b: Bundle, t: Task): Reversibility
  { if t in b.rev then b.rev[t] else IRREVERSIBLE }

  // ---------------- release mode ----------------
  // v1.3.6 (DEFECTIVE): mode keyed on the transmitted class.
  function Mode_trusted(r: Receipt, sampled: bool): Mode
  { if r.claimed_rev == REVERSIBLE && !sampled then Silent else Confirmed }

  // v1.3.7 (RV-3): mode keyed on the class recomputed from the signed bundle
  // and the independently received task. `r` is a live parameter, deliberately
  // unused in the body -- see the methodological note above.
  function Mode_recomputed(b: Bundle, task: Task, r: Receipt, sampled: bool): Mode
  { if RevOf(b, task) == REVERSIBLE && !sampled then Silent else Confirmed }

  // ---------------- DR-9: what release requires ----------------
  // Confirmed mode requires an acknowledgement from a notified party OTHER
  // than the operator (AT-2 distinctness, restated at the release step).
  ghost predicate ReleaseAllowed(m: Mode, p: Pending)
  { m == Silent || (exists w :: w in p.confirmed && w != p.operator) }

  // =========================================================================
  // NEGATIVE RESULTS — the defects, mechanized
  // =========================================================================

  // RV-3 defect: under v1.3.6 a compromised issuer claiming REVERSIBLE obtains
  // Silent mode for an action the SIGNED BUNDLE classifies IRREVERSIBLE.
  lemma RV3_TrustedModeAcceptsDowngrade(b: Bundle, task: Task)
    requires RevOf(b, task) == IRREVERSIBLE
    ensures exists r: Receipt ::
              Mode_trusted(r, false) == Silent
              && RevOf(b, task) == IRREVERSIBLE
  {
    var r := Receipt(REVERSIBLE, task);
    assert Mode_trusted(r, false) == Silent;
  }

  // DR-11 defect: a draw derived from the requester-supplied task is grindable
  // -- the requester searches for a task value that falls outside the sample.
  function Sample_grindable(task: Task, rate: int): bool
  { if rate <= 0 then false else task % 100 < rate }

  lemma DR11_GrindableDrawIsEvadable(rate: int)
    requires 0 < rate < 100
    ensures exists task: Task :: 0 <= task && !Sample_grindable(task, rate)
  {
    assert !Sample_grindable(99, rate);
  }

  // =========================================================================
  // POSITIVE RESULTS — the fixes
  // =========================================================================

  // RV-3 fixed: the recomputed mode is the SAME for every receipt. `r` is an
  // argument, so this constrains the body, not the signature.
  lemma RV3_ModeIndependentOfReceipt(b: Bundle, task: Task, sampled: bool)
    ensures forall r1: Receipt, r2: Receipt ::
              Mode_recomputed(b, task, r1, sampled)
              == Mode_recomputed(b, task, r2, sampled)
  { }

  // RV-1 fixed: an action absent from reversibility.json can never be Silent.
  lemma RV1_UnclassifiedNeverSilent(b: Bundle, task: Task, sampled: bool)
    requires task !in b.rev
    ensures forall r: Receipt :: Mode_recomputed(b, task, r, sampled) == Confirmed
  { }

  // DR-9 end-to-end: for an IRREVERSIBLE action, no receipt and no sampling
  // draw permits release without an acknowledgement from a NON-OPERATOR party.
  // This is the composition of RV-3 and DR-9 and the statement worth having.
  lemma DR9_IrreversibleRequiresNonOperatorAck(
      b: Bundle, task: Task, p: Pending)
    requires RevOf(b, task) == IRREVERSIBLE
    ensures forall r: Receipt, sampled: bool ::
              ReleaseAllowed(Mode_recomputed(b, task, r, sampled), p) ==>
                exists w :: w in p.confirmed && w != p.operator
  { }

  // Corollary, stated separately because it is the operationally load-bearing
  // one: an operator cannot self-release an irreversible action.
  lemma DR9_OperatorCannotSelfRelease(b: Bundle, task: Task, p: Pending)
    requires RevOf(b, task) == IRREVERSIBLE
    requires p.confirmed <= {p.operator}          // only the operator acked
    ensures forall r: Receipt, sampled: bool ::
              !ReleaseAllowed(Mode_recomputed(b, task, r, sampled), p)
  { }

  // DR-11 fixed: the draw is supplied by the Executor; the task is a live
  // parameter and is ignored, so no requester-chosen value moves the outcome.
  function Sample_isolated(draw: int, task: Task, rate: int): bool
  { if rate <= 0 then false else draw % 100 < rate }

  lemma DR11_DrawIndependentOfRequester(draw: int, rate: int)
    ensures forall t1: Task, t2: Task ::
              Sample_isolated(draw, t1, rate) == Sample_isolated(draw, t2, rate)
  { }

  // =========================================================================
  // NON-VACUITY WITNESSES
  // Every theorem above is a negative or an equality. Without these, they
  // could all hold because nothing ever releases.
  // =========================================================================

  lemma NonVacuity_ReversibleUnsampledReleasesSilently(
      b: Bundle, task: Task, r: Receipt, p: Pending)
    requires RevOf(b, task) == REVERSIBLE
    ensures Mode_recomputed(b, task, r, false) == Silent
    ensures ReleaseAllowed(Mode_recomputed(b, task, r, false), p)
  { }

  lemma NonVacuity_IrreversibleReleasesWithAck(
      b: Bundle, task: Task, r: Receipt, operator: Party, approver: Party)
    requires approver != operator
    ensures ReleaseAllowed(Mode_recomputed(b, task, r, true),
                           Pending(operator, {approver}))
  {
    var p := Pending(operator, {approver});
    assert approver in p.confirmed && approver != p.operator;
  }

  // Sampling actually fires for some draw -- DR-10 is not a dead rule.
  lemma NonVacuity_SamplingCanFire(rate: int, task: Task)
    requires 0 < rate
    ensures Sample_isolated(0, task, rate)
  { }
}

// ============================================================================
// PART V — HYBRID SIGNATURE COMPOSITION (v1.3.8)
// ============================================================================
// Models CR-3/CR-4 per the ANSSI hybridation doctrine: a post-quantum
// algorithm is combined with a well-studied classical one, and BOTH must
// verify. The theorem worth having is that the composition survives the total
// break of either primitive -- which is the entire reason to pay for two.
//
// This models COMPOSITION, not cryptography. "Broken primitive" is modelled as
// "the attacker can produce an accepting signature for any message under that
// primitive". Whether ML-DSA or Ed25519 actually resists anything is A-3.
// ============================================================================

module ACP_HybridSignature {

  datatype Primitive = Classical | PostQuantum
  type Key = int
  type Msg = int

  // Per-primitive verification, uninterpreted.
  ghost predicate Verifies(p: Primitive, k: Key, m: Msg, sig: Msg)

  datatype HybridSig = HybridSig(classical: Msg, pq: Msg)

  // CR-3: composition is AND.
  ghost predicate VerifyHybrid_AND(k: Key, m: Msg, s: HybridSig)
  { Verifies(Classical, k, m, s.classical) && Verifies(PostQuantum, k, m, s.pq) }

  // The tempting-but-wrong composition, mechanized so the difference is not a
  // matter of opinion.
  ghost predicate VerifyHybrid_OR(k: Key, m: Msg, s: HybridSig)
  { Verifies(Classical, k, m, s.classical) || Verifies(PostQuantum, k, m, s.pq) }

  // "Primitive p is broken": there is a forgery procedure producing an
  // accepting signature for every message under p. Modelled with an explicit
  // Skolem function rather than a nested existential -- the nested form gives
  // the solver no trigger for the outer quantifier, so it cannot be
  // instantiated at a specific message. This is a modelling choice, not a
  // weakening: `Forge` IS the attacker's algorithm.
  ghost function Forge(p: Primitive, k: Key, m: Msg): Msg

  ghost predicate Broken(p: Primitive, k: Key)
  { forall m: Msg :: Verifies(p, k, m, Forge(p, k, m)) }

  // =========================================================================
  // THE THEOREM: AND survives a single broken primitive.
  // =========================================================================
  // If the post-quantum primitive is broken but the classical one still binds
  // (the attacker cannot sign message m classically), no hybrid signature
  // verifies for m. Symmetrically below.
  lemma CR3_AND_SurvivesPQBreak(k: Key, m: Msg)
    requires Broken(PostQuantum, k)
    requires forall sig: Msg :: !Verifies(Classical, k, m, sig)
    ensures forall s: HybridSig :: !VerifyHybrid_AND(k, m, s)
  { }

  lemma CR3_AND_SurvivesClassicalBreak(k: Key, m: Msg)
    requires Broken(Classical, k)
    requires forall sig: Msg :: !Verifies(PostQuantum, k, m, sig)
    ensures forall s: HybridSig :: !VerifyHybrid_AND(k, m, s)
  { }

  // =========================================================================
  // THE COUNTER-THEOREM: OR does not. One break is total.
  // =========================================================================
  lemma CR3_OR_CollapsesOnSingleBreak(k: Key, m: Msg)
    requires Broken(PostQuantum, k)
    ensures exists s: HybridSig :: VerifyHybrid_OR(k, m, s)
  {
    var forged := Forge(PostQuantum, k, m);
    assert Verifies(PostQuantum, k, m, forged);
    var s := HybridSig(0, forged);
    assert Verifies(PostQuantum, k, m, s.pq);
    assert VerifyHybrid_OR(k, m, s);
  }

  // Corollary, and the operational point: an OR composition is WEAKER than
  // either primitive alone -- the attacker picks whichever is weaker, so
  // adding a second algorithm under OR strictly reduces security.
  lemma CR3_OR_IsWeakerThanEitherAlone(k: Key, m: Msg)
    requires Broken(Classical, k) || Broken(PostQuantum, k)
    ensures exists s: HybridSig :: VerifyHybrid_OR(k, m, s)
  {
    if Broken(PostQuantum, k) {
      var f := Forge(PostQuantum, k, m);
      assert Verifies(PostQuantum, k, m, f);
      assert VerifyHybrid_OR(k, m, HybridSig(0, f));
    } else {
      assert Broken(Classical, k);
      var f := Forge(Classical, k, m);
      assert Verifies(Classical, k, m, f);
      assert VerifyHybrid_OR(k, m, HybridSig(f, 0));
    }
  }

  // =========================================================================
  // NON-VACUITY: the AND composition does accept honest signatures.
  // Without this, the theorems above hold because nothing ever verifies.
  // =========================================================================
  lemma NonVacuity_HonestHybridVerifies(k: Key, m: Msg, sc: Msg, sq: Msg)
    requires Verifies(Classical, k, m, sc)
    requires Verifies(PostQuantum, k, m, sq)
    ensures VerifyHybrid_AND(k, m, HybridSig(sc, sq))
  { }

  // =========================================================================
  // CR-4: suite downgrade. A verifier that accepts the suite named by the
  // message's own issuer can be walked down to the weakest suite; a verifier
  // holding a signed floor cannot.
  // =========================================================================
  datatype Suite = ClassicalOnly | Hybrid
  function Rank(s: Suite): int { match s case ClassicalOnly => 0 case Hybrid => 1 }

  // `claimed` is a live parameter of both, so the independence lemma below
  // constrains the BODY, not the signature (see Part IV methodological note).
  ghost predicate Accept_issuerChosen(floor: Suite, claimed: Suite)
  { true }

  ghost predicate Accept_floorEnforced(floor: Suite, claimed: Suite)
  { Rank(claimed) >= Rank(floor) }

  lemma CR4_IssuerChosenAcceptsDowngrade(floor: Suite)
    requires floor == Hybrid
    ensures Accept_issuerChosen(floor, ClassicalOnly)
  { }

  lemma CR4_FloorRefusesDowngrade(floor: Suite)
    requires floor == Hybrid
    ensures !Accept_floorEnforced(floor, ClassicalOnly)
    ensures Accept_floorEnforced(floor, Hybrid)
  { }
}

