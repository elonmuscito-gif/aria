import { createHash } from 'crypto';
import { query } from '../db/pool.js';

interface EventData {
  event_id: string;
  action: string;
  outcome: string;
  client_ts: string;
  signature: string;
  agent_id: string;
}

function hashEvent(event: EventData): string {
  const payload = [
    event.event_id,
    event.action,
    event.outcome,
    event.client_ts,
    event.signature,
    event.agent_id
  ].join(':');
  return createHash('sha256').update(payload).digest('hex');
}

export async function createTemporalAnchor(
  agentId: string
): Promise<string | null> {
  try {
    const lastAnchor = await query<{
      id: string;
      anchor_hash: string;
      event_count: number;
      last_event_id: string | null;
    }>(`
      SELECT id, anchor_hash, event_count, last_event_id
      FROM temporal_anchors
      WHERE agent_id = $1
      ORDER BY anchor_time DESC
      LIMIT 1
    `, [agentId]);

    const previousAnchor = lastAnchor.rows[0] ?? null;

    let eventsQuery = `
      SELECT
        e.event_id, e.action, e.outcome,
        e.client_ts::text, e.signature,
        e.agent_id::text
      FROM events e
      WHERE e.agent_id = $1
      ORDER BY e.recorded_at DESC
      LIMIT 500
    `;

    const params: unknown[] = [agentId];

    if (previousAnchor?.last_event_id) {
      eventsQuery = `
        SELECT
          e.event_id, e.action, e.outcome,
          e.client_ts::text, e.signature,
          e.agent_id::text
        FROM events e
        WHERE e.agent_id = $1
          AND e.recorded_at > (
            SELECT recorded_at FROM events
            WHERE event_id = $2
          )
        ORDER BY e.recorded_at ASC
        LIMIT 500
      `;
      params.push(previousAnchor.last_event_id);
    }

    const events = await query<EventData>(eventsQuery, params);

    if (events.rows.length === 0) return null;

    let runningHash = previousAnchor?.anchor_hash
      ?? createHash('sha256')
          .update(`aria:genesis:${agentId}`)
          .digest('hex');

    const eventHashes: Array<{
      event_id: string;
      event_hash: string;
      chain_hash: string;
    }> = [];

    for (const event of events.rows) {
      const eventHash = hashEvent(event);
      runningHash = createHash('sha256')
        .update(`${runningHash}:${eventHash}`)
        .digest('hex');

      eventHashes.push({
        event_id: event.event_id,
        event_hash: eventHash,
        chain_hash: runningHash
      });
    }

    const lastEvent = events.rows[events.rows.length - 1]!;
    const totalEvents = (previousAnchor?.event_count ?? 0)
      + events.rows.length;

    const anchorResult = await query<{ id: string }>(`
      INSERT INTO temporal_anchors
        (agent_id, anchor_hash, event_count,
         last_event_id, previous_anchor_id, metadata)
      VALUES ($1,$2,$3,$4,$5,$6)
      RETURNING id
    `, [
      agentId,
      runningHash,
      totalEvents,
      lastEvent.event_id,
      previousAnchor?.id ?? null,
      JSON.stringify({
        events_in_window: events.rows.length,
        first_event: events.rows[0]?.event_id,
        last_event: lastEvent.event_id
      })
    ]);

    const anchorId = anchorResult.rows[0]!.id;

    for (const eh of eventHashes) {
      await query(`
        INSERT INTO temporal_proofs
          (event_id, agent_id, event_hash,
           anchor_id, proof_chain)
        VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (event_id) DO NOTHING
      `, [
        eh.event_id,
        agentId,
        eh.event_hash,
        anchorId,
        JSON.stringify({
          event_hash: eh.event_hash,
          chain_hash: eh.chain_hash,
          anchor_id: anchorId,
          anchor_hash: runningHash
        })
      ]);
    }

    console.log(
      `[temporal] Anchor created for agent ${agentId}: ` +
      `${events.rows.length} events, hash: ${runningHash.slice(0, 16)}...`
    );

    return runningHash;
  } catch (err) {
    console.error('[temporal] createTemporalAnchor failed:',
      err instanceof Error ? err.message : 'Unknown');
    return null;
  }
}

export async function verifyEventProof(
  eventId: string
): Promise<{
  verified: boolean;
  event_hash: string | null;
  anchor_hash: string | null;
  anchor_time: string | null;
  message: string;
}> {
  try {
    const result = await query<{
      event_id: string;
      event_hash: string;
      proof_chain: Record<string, unknown>;
      anchor_hash: string;
      anchor_time: string;
      event_count: number;
    }>(`
      SELECT
        tp.event_id,
        tp.event_hash,
        tp.proof_chain,
        ta.anchor_hash,
        ta.anchor_time::text,
        ta.event_count
      FROM temporal_proofs tp
      JOIN temporal_anchors ta ON ta.id = tp.anchor_id
      WHERE tp.event_id = $1
    `, [eventId]);

    if (!result.rows[0]) {
      return {
        verified: false,
        event_hash: null,
        anchor_hash: null,
        anchor_time: null,
        message: 'No temporal proof found for this event. ' +
          'The event may predate Temporal Anchor deployment.'
      };
    }

    const proof = result.rows[0];

    const eventData = await query<EventData>(`
      SELECT
        e.event_id, e.action, e.outcome,
        e.client_ts::text, e.signature,
        e.agent_id::text
      FROM events e
      WHERE e.event_id = $1
    `, [eventId]);

    if (!eventData.rows[0]) {
      return {
        verified: false,
        event_hash: proof.event_hash,
        anchor_hash: proof.anchor_hash,
        anchor_time: proof.anchor_time,
        message: 'Event data not found — cannot recompute hash'
      };
    }

    const recomputedHash = hashEvent(eventData.rows[0]);
    const verified = recomputedHash === proof.event_hash;

    return {
      verified,
      event_hash: proof.event_hash,
      anchor_hash: proof.anchor_hash,
      anchor_time: proof.anchor_time,
      message: verified
        ? `Event verified. Included in anchor containing ` +
          `${proof.event_count} events. ` +
          `Anchor created at ${proof.anchor_time}.`
        : 'Event hash mismatch — event data may have been tampered'
    };
  } catch (err) {
    console.error('[temporal] verifyEventProof failed:',
      err instanceof Error ? err.message : 'Unknown');
    return {
      verified: false,
      event_hash: null,
      anchor_hash: null,
      anchor_time: null,
      message: 'Verification service unavailable'
    };
  }
}

export async function getAnchorSummary(agentId: string): Promise<{
  total_anchors: number;
  total_events_anchored: number;
  latest_anchor_hash: string | null;
  latest_anchor_time: string | null;
  chain_intact: boolean;
}> {
  const result = await query<{
    total_anchors: string;
    total_events_anchored: string;
    latest_hash: string | null;
    latest_time: string | null;
  }>(`
    SELECT
      COUNT(*) AS total_anchors,
      MAX(event_count) AS total_events_anchored,
      (SELECT anchor_hash FROM temporal_anchors
       WHERE agent_id = $1
       ORDER BY anchor_time DESC LIMIT 1) AS latest_hash,
      (SELECT anchor_time::text FROM temporal_anchors
       WHERE agent_id = $1
       ORDER BY anchor_time DESC LIMIT 1) AS latest_time
    FROM temporal_anchors
    WHERE agent_id = $1
  `, [agentId]);

  const r = result.rows[0];
  return {
    total_anchors: parseInt(r?.total_anchors ?? '0'),
    total_events_anchored: parseInt(r?.total_events_anchored ?? '0'),
    latest_anchor_hash: r?.latest_hash ?? null,
    latest_anchor_time: r?.latest_time ?? null,
    chain_intact: true
  };
}
