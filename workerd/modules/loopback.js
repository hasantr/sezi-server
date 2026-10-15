export default {
  // The development loopback to wrangler's Node process does not exist in production. The
  // storage workers bind it for development-only paths; they get a refusal, never a connection.
  fetch() { return new Response("loopback not available", { status: 503 }); }
};
