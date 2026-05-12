// raxis/live-e2e/seed/mongo/01-seed.js
//
// Idempotent mongo seed for the extended e2e scenario
// (`raxis/specs/v2/e2e-extended-scenario.md` §3.2).
//
// Mounted into the mongodb container at
// `/docker-entrypoint-initdb.d/01-seed.js` by
// `live-e2e/docker-compose.extended.e2e.yml`. The official mongo
// image runs every `*.js` in this directory at first boot via
// `mongosh`. The harness's preflight additionally re-applies it
// against a long-running container so re-runs converge.
//
// Determinism contract — see the matching block in
// `../postgres/01-seed.sql`. The canonical expected output in
// `live-e2e/seed/expected/mongo_docs.json` mirrors this generator.
//
// Schema (mongo is schemaless; this is the conventional shape):
//   {
//     _id:        ObjectId("65500000000000000000NNNN"),  // NNNN hex zero-padded
//     doc_id:     "doc-NNNN",                              // NNNN decimal zero-padded
//     payload:    { ... },                                  // see formula below
//     created_at: NumberLong(1700000000)
//   }
//
// Payload formula (per doc, where i ∈ 1..25):
//   {
//     "index": i,
//     "label": "doc-NNNN",
//     "magic": ((i * 2654435761) mod 2^32),  -- Knuth multiplicative hash
//     "tag":   ["alpha", "beta", "gamma"][(i - 1) mod 3]
//   }
//
// _id derivation: a fixed 20-char hex prefix `65500000000000000000`
// (12 bytes, of which the high 4 bytes are zero-padded but happen to
// look like a unix-timestamp-ish prefix to operators familiar with
// ObjectId structure) followed by 4 hex chars zero-padded from the
// decimal index. This keeps every _id 24 chars exactly and stable
// across re-seeds.

const KNUTH_CONST = 2654435761;
const TAGS = ["alpha", "beta", "gamma"];

const targetDb = db.getSiblingDB("raxis_e2e_mongo");
const coll = targetDb.getCollection("seeded_docs");

for (let i = 1; i <= 25; i++) {
    const idxStr = String(i).padStart(4, "0");
    const hexIdx = i.toString(16).padStart(4, "0");
    const objectIdHex = "65500000000000000000" + hexIdx;
    const docId = "doc-" + idxStr;
    const magic = (i * KNUTH_CONST) % 4294967296;
    const tag = TAGS[(i - 1) % 3];

    coll.replaceOne(
        { _id: ObjectId(objectIdHex) },
        {
            _id: ObjectId(objectIdHex),
            doc_id: docId,
            payload: {
                index: i,
                label: docId,
                magic: NumberLong(magic),
                tag: tag,
            },
            created_at: NumberLong(1700000000),
        },
        { upsert: true },
    );
}

const finalCount = coll.countDocuments({});
if (finalCount !== 25) {
    throw new Error(
        "seeded_docs expected 25 documents, found " + finalCount,
    );
}
print("[raxis-e2e seed] seeded_docs ready, count=" + finalCount);
