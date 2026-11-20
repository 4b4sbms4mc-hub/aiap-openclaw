import { createHash, randomUUID } from 'node:crypto';

// SessionController.prompt from DSH 0.2.2-rc.5. An unknown host keeps ordinary
// prompts working and leaves automatic proposals inactive.
const supportedPrompt = '083181f9234d76646c1d6d0664e022b1ec3b7307f8ebb025195c0af1ed6a0976';

export function bindOwnerIngress(controller) {
  const prototype = Object.getPrototypeOf(controller);
  const descriptor = Object.getOwnPropertyDescriptor(prototype, 'prompt');
  const original = descriptor?.value;
  const commands = controller.commands;
  const submit = commands?.prompt;
  if (typeof original !== 'function' || typeof submit !== 'function'
      || !descriptor.writable || createHash('sha256')
        .update(Function.prototype.toString.call(original)).digest('hex') !== supportedPrompt) return;

  const proofs = new Map();
  const lifetime = 120_000;
  let directRequest;
  const wrappedSubmit = function (request, source) {
    if (request && directRequest === request && source?.kind === 'user' && source.rpcId === request.requestId
        && !Object.hasOwn(source, 'principal')) {
      directRequest = undefined;
      const now = performance.now();
      for (const [id, proof] of proofs) {
        if (proof.until > now) break;
        proofs.delete(id);
      }
      if (proofs.size < 256 && request.content.length === 1 && request.content[0]?.type === 'text'
          && typeof request.content[0].text === 'string' && request.content[0].text.length <= 400) {
        // DSH clones message metadata across its queue. Only this process
        // retains the matching proof, and a successful check consumes it.
        const id = randomUUID();
        proofs.set(id, {
          sessionId: request.sessionId, rpcId: request.requestId,
          digest: createHash('sha256').update(request.content[0].text).digest('hex'), until: now + lifetime,
        });
        source = { ...source, aiapCaptureProof: id };
      }
    }
    return Reflect.apply(submit, this, [request, source]);
  };
  const wrappedPrompt = new Proxy(original, {
    apply(fn, receiver, args) {
      const [request, signal] = args;
      const invocation = receiver.ctx.invocation;
      const previous = directRequest;
      directRequest = receiver.commands === commands && invocation?.signal === signal && signal && !signal.aborted
        && invocation.request?.namespace === 'session' && invocation.request?.method === 'prompt'
        && invocation.peer?.principal?.kind === 'owner' && request?.content?.length > 0 ? request : undefined;
      try {
        // This exact host method delegates synchronously before yielding.
        return Reflect.apply(fn, receiver, args);
      } finally {
        directRequest = previous;
      }
    },
  });
  commands.prompt = wrappedSubmit;
  Object.defineProperty(prototype, 'prompt', { ...descriptor, value: wrappedPrompt });
  return {
    consume(sessionId, source, text) {
      if (source?.kind !== 'user' || Object.hasOwn(source, 'principal')) return false;
      const id = source.aiapCaptureProof;
      const proof = proofs.get(id);
      if (!proof || proof.until <= performance.now() || proof.sessionId !== sessionId
          || proof.rpcId !== source.rpcId || typeof text !== 'string'
          || proof.digest !== createHash('sha256').update(text).digest('hex')) return false;
      proofs.delete(id);
      return true;
    },
    dispose() {
      proofs.clear();
      if (commands.prompt === wrappedSubmit) commands.prompt = submit;
      if (prototype.prompt === wrappedPrompt) Object.defineProperty(prototype, 'prompt', descriptor);
    },
  };
}
