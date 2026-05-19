import assert from 'assert';
import { createHmac } from 'crypto';
import { randomUUID } from 'crypto';

const BASE_URL = process.env.TEST_URL || 'https://ariatrust.org';
const SETUP_KEY = process.env.SETUP_KEY ||
  '9505558bab1d7dba616f7f575ab035cd74ae494befd5c29dd2d42979ab66f3fb';

console.log(`Running integration tests against ${BASE_URL}...`);

// ── TEST HELPERS ──────────────────────────────────────
let testApiKey: string;
let testAgentDid: string;
let testAgentSecret: string;
const testEmail = `test-${Date.now()}@ariatrust.org`;

async function apiKey(
  endpoint: string,
  options: RequestInit = {}
): Promise<Response> {
  return fetch(`${BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${testApiKey}`,
      ...options.headers
    }
  });
}

async function adminApi(
  endpoint: string,
  options: RequestInit = {}
): Promise<Response> {
  return fetch(`${BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-Setup-Key': SETUP_KEY,
      ...options.headers
    }
  });
}

function signEvent(
  eventId: string,
  agentDid: string,
  action: string,
  outcome: string,
  timestamp: string,
  secret: string
): string {
  const payload =
    `${eventId}:${agentDid}:${action}:${outcome}:${timestamp}`;
  return createHmac('sha256', secret)
    .update(payload).digest('hex');
}

async function createTestEvent(
  action: string,
  outcome: 'success' | 'error' | 'anomaly' = 'success'
) {
  const eventId = randomUUID();
  const timestamp = new Date().toISOString();
  const signature = signEvent(
    eventId, testAgentDid, action, outcome,
    timestamp, testAgentSecret
  );

  const res = await apiKey('/v1/events', {
    method: 'POST',
    body: JSON.stringify({
      eventId,
      agentDid: testAgentDid,
      action,
      outcome,
      withinScope: true,
      durationMs: 100,
      timestamp,
      signature
    })
  });
  return res;
}

// ── CLEANUP ────────────────────────────────────────────
async function cleanup() {
  if (testAgentDid) {
    await apiKey(`/v1/agents/${testAgentDid}`, {
      method: 'DELETE'
    }).catch(() => {});
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GROUP 1: SETUP — Create test account via setup endpoint
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function testSetup() {
  console.log('\n--- GROUP 1: Setup ---');

  // Test 1: Create API key via setup endpoint
  const setupRes = await fetch(`${BASE_URL}/v1/setup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      setup_key: SETUP_KEY,
      owner_email: testEmail
    })
  });
  assert.strictEqual(setupRes.status, 201,
    'Setup should create API key');
  const setupData = await setupRes.json() as {
    api_key: string
  };
  testApiKey = setupData.api_key;
  assert.ok(testApiKey, 'API key should be returned');
  console.log('✅ Test 1: Setup creates API key');

  // Test 2: Duplicate setup rejected
  const dupRes = await fetch(`${BASE_URL}/v1/setup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      setup_key: SETUP_KEY,
      owner_email: testEmail
    })
  });
  assert.strictEqual(dupRes.status, 409,
    'Duplicate setup should be rejected');
  console.log('✅ Test 2: Duplicate setup rejected');

  // Test 3: Invalid setup key rejected
  const invalidRes = await fetch(`${BASE_URL}/v1/setup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      setup_key: 'invalid-key',
      owner_email: 'test2@test.com'
    })
  });
  assert.strictEqual(invalidRes.status, 403,
    'Invalid setup key should be rejected');
  console.log('✅ Test 3: Invalid setup key rejected');
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GROUP 2: AGENTS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function testAgents() {
  console.log('\n--- GROUP 2: Agents ---');

  // Test 4: Register agent
  const regRes = await apiKey('/v1/agents', {
    method: 'POST',
    body: JSON.stringify({
      name: 'integration-test-agent',
      scope: ['read:data', 'write:data', 'send:email']
    })
  });
  assert.strictEqual(regRes.status, 201,
    'Agent registration should succeed');
  const regData = await regRes.json() as {
    agent: { did: string };
    secret: string;
  };
  testAgentDid = regData.agent.did;
  testAgentSecret = regData.secret;
  assert.ok(
    testAgentDid.startsWith('did:agentrust:'),
    'DID format correct'
  );
  console.log('✅ Test 4: Agent registered with valid DID');

  // Test 5: Agent appears in list
  const listRes = await apiKey('/v1/agents');
  const listData = await listRes.json() as {
    agents: Array<{ did: string }>
  };
  const found = listData.agents.find(
    a => a.did === testAgentDid
  );
  assert.ok(found, 'Agent should appear in list');
  console.log('✅ Test 5: Agent appears in list');

  // Test 6: Get agent detail
  const detailRes = await apiKey(
    `/v1/agents/${testAgentDid}`
  );
  assert.strictEqual(detailRes.status, 200);
  const detailData = await detailRes.json() as {
    agent: { did: string; scope: string[] }
  };
  assert.deepStrictEqual(
    detailData.agent.scope,
    ['read:data', 'write:data', 'send:email']
  );
  console.log('✅ Test 6: Agent detail returns correct scope');

  // Test 7: Invalid scope format rejected
  const badScopeRes = await apiKey('/v1/agents', {
    method: 'POST',
    body: JSON.stringify({
      name: 'bad-agent',
      scope: ['INVALID_SCOPE', 'read data']
    })
  });
  assert.strictEqual(badScopeRes.status, 400,
    'Invalid scope format should be rejected');
  console.log('✅ Test 7: Invalid scope format rejected');

  // Test 8: Recover agent secret
  const secretRes = await apiKey(
    `/v1/agents/${testAgentDid}/secret`
  );
  assert.strictEqual(secretRes.status, 200);
  const secretData = await secretRes.json() as {
    secret: string
  };
  assert.strictEqual(
    secretData.secret, testAgentSecret,
    'Recovered secret must match original'
  );
  console.log('✅ Test 8: Agent secret recoverable');
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GROUP 3: EVENTS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function testEvents() {
  console.log('\n--- GROUP 3: Events ---');

  // Test 9: Valid event accepted
  const res = await createTestEvent('read:data', 'success');
  assert.strictEqual(res.status, 202,
    'Valid event should be accepted');
  const data = await res.json() as {
    accepted: boolean;
    eventId: string;
    insights: {
      scope: { valid: boolean };
      signature: { valid: boolean };
    }
  };
  assert.strictEqual(data.accepted, true);
  assert.strictEqual(data.insights.scope.valid, true);
  assert.strictEqual(data.insights.signature.valid, true);
  console.log('✅ Test 9: Valid event accepted with insights');

  // Test 10: Scope violation detected server-side
  const violationRes = await createTestEvent(
    'delete:database', 'error'
  );
  assert.strictEqual(violationRes.status, 202);
  const violationData = await violationRes.json() as {
    insights: { scope: { valid: boolean } }
  };
  assert.strictEqual(
    violationData.insights.scope.valid, false,
    'Out-of-scope action should be flagged'
  );
  console.log('✅ Test 10: Scope violation detected server-side');

  // Test 11: Invalid signature detected
  const eventId = randomUUID();
  const timestamp = new Date().toISOString();
  const badSigRes = await apiKey('/v1/events', {
    method: 'POST',
    body: JSON.stringify({
      eventId,
      agentDid: testAgentDid,
      action: 'read:data',
      outcome: 'success',
      withinScope: true,
      durationMs: 100,
      timestamp,
      signature: 'invalid-signature-abc123'
    })
  });
  assert.strictEqual(badSigRes.status, 202);
  const badSigData = await badSigRes.json() as {
    insights: { signature: { valid: boolean } }
  };
  assert.strictEqual(
    badSigData.insights.signature.valid, false,
    'Invalid signature should be detected'
  );
  console.log('✅ Test 11: Invalid signature detected');

  // Test 12: Duplicate event rejected
  const dupId = randomUUID();
  const dupTimestamp = new Date().toISOString();
  const dupSig = signEvent(
    dupId, testAgentDid, 'read:data',
    'success', dupTimestamp, testAgentSecret
  );
  const eventBody = {
    eventId: dupId,
    agentDid: testAgentDid,
    action: 'read:data',
    outcome: 'success',
    withinScope: true,
    durationMs: 100,
    timestamp: dupTimestamp,
    signature: dupSig
  };
  await apiKey('/v1/events', {
    method: 'POST',
    body: JSON.stringify(eventBody)
  });
  const dupRes = await apiKey('/v1/events', {
    method: 'POST',
    body: JSON.stringify(eventBody)
  });
  assert.strictEqual(dupRes.status, 409,
    'Duplicate event should be rejected');
  console.log('✅ Test 12: Duplicate event rejected');

  // Test 13: Timestamp too old rejected
  const oldTimestamp = new Date(
    Date.now() - 10 * 60 * 1000
  ).toISOString();
  const oldId = randomUUID();
  const oldSig = signEvent(
    oldId, testAgentDid, 'read:data',
    'success', oldTimestamp, testAgentSecret
  );
  const oldRes = await apiKey('/v1/events', {
    method: 'POST',
    body: JSON.stringify({
      eventId: oldId,
      agentDid: testAgentDid,
      action: 'read:data',
      outcome: 'success',
      withinScope: true,
      durationMs: 100,
      timestamp: oldTimestamp,
      signature: oldSig
    })
  });
  assert.strictEqual(oldRes.status, 400,
    'Old timestamp should be rejected');
  console.log('✅ Test 13: Old timestamp rejected');

  // Test 14: Batch events accepted
  const batchEvents = Array.from({ length: 5 }, (_, i) => {
    const id = randomUUID();
    const ts = new Date().toISOString();
    return {
      eventId: id,
      agentDid: testAgentDid,
      action: 'read:data',
      outcome: 'success',
      withinScope: true,
      durationMs: 100 + i,
      timestamp: ts,
      signature: signEvent(
        id, testAgentDid, 'read:data',
        'success', ts, testAgentSecret
      )
    };
  });
  const batchRes = await apiKey('/v1/events/batch', {
    method: 'POST',
    body: JSON.stringify({ events: batchEvents })
  });
  assert.strictEqual(batchRes.status, 202,
    'Batch events should be accepted');
  const batchData = await batchRes.json() as {
    accepted: number; rejected: number
  };
  assert.strictEqual(batchData.accepted, 5,
    'All 5 batch events should be accepted');
  console.log('✅ Test 14: Batch of 5 events accepted');

  // Test 15: Batch over 500 rejected
  const bigBatch = Array.from({ length: 501 }, () => ({
    eventId: randomUUID(),
    agentDid: testAgentDid,
    action: 'read:data',
    outcome: 'success',
    withinScope: true,
    durationMs: 100,
    timestamp: new Date().toISOString(),
    signature: 'fake'
  }));
  const bigBatchRes = await apiKey('/v1/events/batch', {
    method: 'POST',
    body: JSON.stringify({ events: bigBatch })
  });
  assert.strictEqual(bigBatchRes.status, 400,
    'Batch over 500 should be rejected');
  console.log('✅ Test 15: Batch over 500 rejected');

  // Test 16: Events listable with filter
  const listRes = await apiKey(
    `/v1/events?agentDid=${testAgentDid}&limit=10`
  );
  assert.strictEqual(listRes.status, 200);
  const listData = await listRes.json() as {
    events: unknown[]
  };
  assert.ok(listData.events.length > 0,
    'Events should be listable');
  console.log('✅ Test 16: Events listable with agent filter');

  // Test 17: CSV export works
  const exportRes = await apiKey(
    `/v1/events/export?agentDid=${testAgentDid}&format=csv&type=all`
  );
  assert.strictEqual(exportRes.status, 200);
  const csv = await exportRes.text();
  assert.ok(csv.includes('event_id'),
    'CSV should have headers');
  console.log('✅ Test 17: CSV export works');
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GROUP 4: ARIA GATE end-to-end
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function testGate() {
  console.log('\n--- GROUP 4: ARIA Gate ---');

  // Test 18: Create gate request
  const gateRes = await apiKey('/v1/gate/request', {
    method: 'POST',
    body: JSON.stringify({
      agentDid: testAgentDid,
      action: 'delete:records',
      context: { test: true }
    })
  });
  assert.strictEqual(gateRes.status, 201,
    'Gate request should be created');
  const gateData = await gateRes.json() as {
    requestId: string; status: string
  };
  assert.strictEqual(gateData.status, 'pending');
  const requestId = gateData.requestId;
  console.log('✅ Test 18: Gate request created');

  // Test 19: Poll gate request — pending
  const pollRes = await apiKey(
    `/v1/gate/request/${requestId}`
  );
  assert.strictEqual(pollRes.status, 200);
  const pollData = await pollRes.json() as {
    status: string
  };
  assert.strictEqual(pollData.status, 'pending');
  console.log('✅ Test 19: Gate request polling returns pending');

  // Test 20: Approve gate request
  const approveRes = await apiKey(
    `/v1/gate/approve/${requestId}`,
    { method: 'POST', body: '{}' }
  );
  assert.strictEqual(approveRes.status, 200);
  const approveData = await approveRes.json() as {
    status: string
  };
  assert.strictEqual(approveData.status, 'approved');
  console.log('✅ Test 20: Gate request approved');

  // Test 21: Poll after approval shows approved
  const poll2Res = await apiKey(
    `/v1/gate/request/${requestId}`
  );
  const poll2Data = await poll2Res.json() as {
    status: string
  };
  assert.strictEqual(poll2Data.status, 'approved');
  console.log('✅ Test 21: Polling after approval shows approved');

  // Test 22: Create and deny gate request
  const gate2Res = await apiKey('/v1/gate/request', {
    method: 'POST',
    body: JSON.stringify({
      agentDid: testAgentDid,
      action: 'export:data',
      context: { test: true }
    })
  });
  const gate2Data = await gate2Res.json() as {
    requestId: string
  };
  const request2Id = gate2Data.requestId;

  const denyRes = await apiKey(
    `/v1/gate/deny/${request2Id}`,
    { method: 'POST', body: '{}' }
  );
  assert.strictEqual(denyRes.status, 200);
  const denyData = await denyRes.json() as {
    status: string
  };
  assert.strictEqual(denyData.status, 'denied');
  console.log('✅ Test 22: Gate request denied');

  // Test 23: Pending list works
  const pendingRes = await apiKey('/v1/gate/pending');
  assert.strictEqual(pendingRes.status, 200);
  console.log('✅ Test 23: Gate pending list accessible');

  // Test 24: Cannot approve already resolved request
  const dupApproveRes = await apiKey(
    `/v1/gate/approve/${requestId}`,
    { method: 'POST', body: '{}' }
  );
  assert.strictEqual(dupApproveRes.status, 404,
    'Cannot approve already resolved request');
  console.log('✅ Test 24: Cannot re-approve resolved request');
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GROUP 5: MERKLE TREE
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function testMerkle() {
  console.log('\n--- GROUP 5: Merkle Tree ---');

  const {
    buildMerkleTree,
    generateProof,
    verifyProof
  } = await import('../utils/merkle.js');

  // Test 25: Empty tree
  const emptyTree = buildMerkleTree([]);
  assert.ok(emptyTree.root, 'Empty tree has root');
  assert.strictEqual(emptyTree.leaves.length, 0);
  console.log('✅ Test 25: Empty Merkle tree handled');

  // Test 26: Single leaf tree
  const singleTree = buildMerkleTree(['leaf1']);
  assert.ok(singleTree.root, 'Single leaf tree has root');
  assert.strictEqual(singleTree.leaves.length, 1);
  console.log('✅ Test 26: Single leaf Merkle tree');

  // Test 27: Odd number of leaves
  const oddTree = buildMerkleTree(['a', 'b', 'c']);
  assert.ok(oddTree.root, 'Odd leaf tree has root');
  assert.strictEqual(oddTree.leaves.length, 3);
  console.log('✅ Test 27: Odd number of leaves handled');

  // Test 28: Generate and verify proof
  const tree = buildMerkleTree(['a', 'b', 'c', 'd']);
  const proof = generateProof(tree, 0);
  assert.ok(proof, 'Proof generated for leaf 0');
  const valid = verifyProof(proof!);
  assert.strictEqual(valid, true, 'Proof should be valid');
  console.log('✅ Test 28: Merkle proof generated and verified');

  // Test 29: Tampered proof fails
  const proof2 = generateProof(tree, 1);
  assert.ok(proof2);
  const tamperedProof = {
    ...proof2!,
    leaf: 'tampered-leaf-hash'
  };
  const tamperedValid = verifyProof(tamperedProof);
  assert.strictEqual(tamperedValid, false,
    'Tampered proof should fail');
  console.log('✅ Test 29: Tampered Merkle proof fails');

  // Test 30: Same leaves always produce same root
  const tree1 = buildMerkleTree(['x', 'y', 'z']);
  const tree2 = buildMerkleTree(['x', 'y', 'z']);
  assert.strictEqual(tree1.root, tree2.root,
    'Same leaves produce same root');
  console.log('✅ Test 30: Deterministic Merkle tree');

  // Test 31: Different leaves produce different roots
  const tree3 = buildMerkleTree(['x', 'y', 'z']);
  const tree4 = buildMerkleTree(['x', 'y', 'w']);
  assert.notStrictEqual(tree3.root, tree4.root,
    'Different leaves produce different roots');
  console.log('✅ Test 31: Different leaves = different roots');
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GROUP 6: ZEROPROOF
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function testZeroproof() {
  console.log('\n--- GROUP 6: ZeroProof ---');

  // Test 32: Proof of Innocence — agent never did X
  const innocenceRes = await apiKey(
    '/v1/zeroproof/innocence',
    {
      method: 'POST',
      body: JSON.stringify({
        agentDid: testAgentDid,
        forbidden_pattern: 'drop:*',
        window_days: 30
      })
    }
  );
  assert.strictEqual(innocenceRes.status, 201);
  const innocenceData = await innocenceRes.json() as {
    verified: boolean;
    claim: string;
    merkle_root: string;
    proof_id: string;
  };
  assert.strictEqual(innocenceData.verified, true,
    'Agent never executed drop:* — innocence proven');
  assert.ok(innocenceData.merkle_root,
    'Proof has merkle root');
  console.log('✅ Test 32: Proof of Innocence verified');

  // Test 33: Proof of Innocence FAILS for known violation
  // Agent DID execute delete:database (scope violation) in Test 10
  const failedProofRes = await apiKey(
    '/v1/zeroproof/innocence',
    {
      method: 'POST',
      body: JSON.stringify({
        agentDid: testAgentDid,
        forbidden_pattern: 'delete:*',
        window_days: 30
      })
    }
  );
  const failedData = await failedProofRes.json() as {
    verified: boolean
  };
  assert.strictEqual(failedData.verified, false,
    'Innocence proof should fail for known violation');
  console.log('✅ Test 33: Innocence proof fails for violations');

  // Test 34: Proof of Consistency
  const consistencyRes = await apiKey(
    '/v1/zeroproof/consistency',
    {
      method: 'POST',
      body: JSON.stringify({
        agentDid: testAgentDid,
        min_success_rate: 50,
        window_days: 30
      })
    }
  );
  assert.strictEqual(consistencyRes.status, 201);
  const consistencyData = await consistencyRes.json() as {
    verified: boolean; claim: string
  };
  assert.ok(consistencyData.claim,
    'Consistency proof has claim');
  console.log(`✅ Test 34: Consistency proof: ${consistencyData.verified}`);

  // Test 35: Proof of Limits
  const limitsRes = await apiKey(
    '/v1/zeroproof/limits',
    {
      method: 'POST',
      body: JSON.stringify({
        agentDid: testAgentDid,
        max_events_per_hour: 1000,
        window_days: 30
      })
    }
  );
  assert.strictEqual(limitsRes.status, 201);
  const limitsData = await limitsRes.json() as {
    verified: boolean
  };
  assert.strictEqual(limitsData.verified, true,
    'Agent under 1000 events/hour');
  console.log('✅ Test 35: Proof of Limits verified');

  // Test 36: Proof list accessible
  // Use proof_id stored from Test 32 (innocenceData already parsed)
  const _proofId = innocenceData.proof_id;
  const listRes = await apiKey(
    `/v1/zeroproof/list/${testAgentDid}`
  );
  assert.strictEqual(listRes.status, 200);
  const listData = await listRes.json() as {
    proofs: unknown[]
  };
  assert.ok(listData.proofs.length > 0,
    'Proofs list should have entries');
  console.log('✅ Test 36: Proof list accessible');
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GROUP 7: TEMPORAL ANCHOR
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function testTemporal() {
  console.log('\n--- GROUP 7: Temporal Anchor ---');

  // Test 37: Create temporal anchor
  const anchorRes = await apiKey(
    `/v1/temporal/anchor/${testAgentDid}`,
    { method: 'POST', body: '{}' }
  );
  assert.ok(
    anchorRes.status === 201 || anchorRes.status === 200,
    'Temporal anchor created'
  );
  const anchorData = await anchorRes.json() as {
    anchor_hash: string | null; message: string
  };
  console.log(`✅ Test 37: Temporal anchor: ${anchorData.message}`);

  // Test 38: Get anchor summary
  const summaryRes = await apiKey(
    `/v1/temporal/anchors/${testAgentDid}`
  );
  assert.strictEqual(summaryRes.status, 200);
  const summaryData = await summaryRes.json() as {
    temporal_anchor: {
      total_anchors: number;
      total_events_anchored: number;
    }
  };
  assert.ok(
    summaryData.temporal_anchor.total_anchors >= 0,
    'Anchor summary accessible'
  );
  console.log('✅ Test 38: Temporal anchor summary accessible');

  // Test 39: List anchors
  const listRes = await apiKey(
    `/v1/temporal/anchors/${testAgentDid}/list`
  );
  assert.strictEqual(listRes.status, 200);
  console.log('✅ Test 39: Temporal anchor list accessible');

  // Test 40: Verify event proof
  const eventsRes = await apiKey(
    `/v1/events?agentDid=${testAgentDid}&limit=1`
  );
  const eventsData = await eventsRes.json() as {
    events: Array<{ event_id: string }>
  };

  if (eventsData.events.length > 0) {
    const eventId = eventsData.events[0]!.event_id;
    const verifyRes = await apiKey(
      `/v1/temporal/verify/${eventId}`
    );
    assert.strictEqual(verifyRes.status, 200);
    const verifyData = await verifyRes.json() as {
      verified: boolean; message: string
    };
    console.log(`✅ Test 40: Event proof: ${verifyData.message.slice(0, 50)}`);
  } else {
    console.log('✅ Test 40: Skipped (no events yet)');
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GROUP 8: SHADOW WITNESS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function testWitness() {
  console.log('\n--- GROUP 8: Shadow Witness ---');

  // Test 41: Register witness source
  const sourceRes = await apiKey('/v1/witness/sources', {
    method: 'POST',
    body: JSON.stringify({
      agentDid: testAgentDid,
      name: 'test-source',
      source_type: 'manual',
      action_pattern: 'read:data'
    })
  });
  assert.ok(
    sourceRes.status === 201 || sourceRes.status === 403,
    'Witness source registration attempted'
  );
  console.log(`✅ Test 41: Witness source registration: ${sourceRes.status}`);

  // Test 42: Get witness summary
  const summaryRes = await apiKey(
    `/v1/witness/agents/${testAgentDid}`
  );
  assert.strictEqual(summaryRes.status, 200);
  const summaryData = await summaryRes.json() as {
    verification_status: string
  };
  assert.ok(summaryData.verification_status,
    'Witness summary has status');
  console.log(`✅ Test 42: Witness summary: ${summaryData.verification_status}`);

  // Test 43: List witness checks
  const checksRes = await apiKey('/v1/witness/checks');
  assert.strictEqual(checksRes.status, 200);
  console.log('✅ Test 43: Witness checks list accessible');
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GROUP 9: ADMIN ENDPOINTS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function testAdmin() {
  console.log('\n--- GROUP 9: Admin ---');

  // Test 44: Admin health
  const healthRes = await adminApi('/v1/admin/health');
  assert.strictEqual(healthRes.status, 200);
  const healthData = await healthRes.json() as {
    status: string; stats: Record<string, unknown>
  };
  assert.strictEqual(healthData.status, 'ok');
  console.log('✅ Test 44: Admin health returns ok');

  // Test 45: Admin users list
  const usersRes = await adminApi('/v1/admin/users');
  assert.strictEqual(usersRes.status, 200);
  const usersData = await usersRes.json() as {
    users: unknown[]
  };
  assert.ok(Array.isArray(usersData.users),
    'Users list is array');
  console.log(`✅ Test 45: Admin lists ${usersData.users.length} users`);

  // Test 46: Admin events list
  const eventsRes = await adminApi('/v1/admin/events');
  assert.strictEqual(eventsRes.status, 200);
  console.log('✅ Test 46: Admin events list accessible');

  // Test 47: Admin gate requests
  const gateRes = await adminApi('/v1/admin/gate');
  assert.strictEqual(gateRes.status, 200);
  console.log('✅ Test 47: Admin gate requests accessible');

  // Test 48: Admin anomalies
  const anomaliesRes = await adminApi('/v1/admin/anomalies');
  assert.strictEqual(anomaliesRes.status, 200);
  console.log('✅ Test 48: Admin anomalies accessible');

  // Test 49: Admin patterns
  const patternsRes = await adminApi('/v1/admin/patterns');
  assert.strictEqual(patternsRes.status, 200);
  console.log('✅ Test 49: Admin patterns accessible');

  // Test 50: Admin blocked IPs
  const ipsRes = await adminApi(
    '/v1/admin/security/blocked-ips'
  );
  assert.strictEqual(ipsRes.status, 200);
  console.log('✅ Test 50: Admin blocked IPs accessible');

  // Test 51: Admin API keys
  const keysRes = await adminApi(
    '/v1/admin/security/api-keys'
  );
  assert.strictEqual(keysRes.status, 200);
  console.log('✅ Test 51: Admin API keys accessible');

  // Test 52: Admin audit log
  const auditRes = await adminApi('/v1/admin/audit-log');
  assert.strictEqual(auditRes.status, 200);
  console.log('✅ Test 52: Admin audit log accessible');

  // Test 53: Admin DB stats
  const dbRes = await adminApi('/v1/admin/db-stats');
  assert.strictEqual(dbRes.status, 200);
  console.log('✅ Test 53: Admin DB stats accessible');

  // Test 54: Admin rejects wrong setup key
  const badAdminRes = await fetch(
    `${BASE_URL}/v1/admin/health`,
    { headers: { 'X-Setup-Key': 'wrong-key' } }
  );
  assert.ok(
    badAdminRes.status === 403 || badAdminRes.status === 429,
    `Admin should reject wrong setup key, got ${badAdminRes.status}`
  );
  console.log('✅ Test 54: Admin rejects wrong setup key');

  // Test 55: Admin webhooks
  const webhooksRes = await adminApi('/v1/admin/webhooks');
  assert.strictEqual(webhooksRes.status, 200);
  console.log('✅ Test 55: Admin webhooks accessible');
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GROUP 10: WEBHOOKS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function testWebhooks() {
  console.log('\n--- GROUP 10: Webhooks ---');

  // Test 56: Register webhook requires HTTPS
  const httpRes = await apiKey('/v1/webhooks', {
    method: 'POST',
    body: JSON.stringify({
      url: 'http://example.com/webhook',
      events: ['anomaly']
    })
  });
  assert.strictEqual(httpRes.status, 400,
    'HTTP webhook URL should be rejected');
  console.log('✅ Test 56: HTTP webhook URL rejected');

  // Test 57: Invalid URL rejected
  const invalidRes = await apiKey('/v1/webhooks', {
    method: 'POST',
    body: JSON.stringify({
      url: 'not-a-url',
      events: ['anomaly']
    })
  });
  assert.strictEqual(invalidRes.status, 400,
    'Invalid URL rejected');
  console.log('✅ Test 57: Invalid webhook URL rejected');

  // Test 58: List webhooks
  const listRes = await apiKey('/v1/webhooks');
  assert.strictEqual(listRes.status, 200);
  console.log('✅ Test 58: Webhook list accessible');
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// MAIN RUNNER
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function runAll() {
  const results: Record<string, boolean> = {};

  const run = async (
    name: string, fn: () => Promise<void>
  ) => {
    try {
      await fn();
      results[name] = true;
    } catch (err) {
      console.error(
        `\n❌ ${name} FAILED:`,
        err instanceof Error ? err.message : String(err)
      );
      results[name] = false;
    }
  };

  await run('Setup', testSetup);
  await run('Agents', testAgents);
  await run('Events', testEvents);
  await run('Gate', testGate);
  await run('Merkle', testMerkle);
  await run('ZeroProof', testZeroproof);
  await run('Temporal', testTemporal);
  await run('Witness', testWitness);
  await run('Admin', testAdmin);
  await run('Webhooks', testWebhooks);

  await cleanup();

  // Summary
  console.log('\n' + '━'.repeat(50));
  console.log('INTEGRATION TEST RESULTS');
  console.log('━'.repeat(50));

  const passed = Object.values(results)
    .filter(Boolean).length;
  const total = Object.keys(results).length;

  Object.entries(results).forEach(([name, ok]) => {
    console.log(`${ok ? '[PASS]' : '[FAIL]'} ${name}`);
  });

  console.log('━'.repeat(50));
  console.log(`${passed}/${total} groups passed`);

  if (passed < total) {
    process.exit(1);
  }
}

runAll().catch(err => {
  console.error('Fatal:', err.message);
  process.exit(1);
});
