package dev.sigstore.trust;

import dev.sigstore.tuf.MutableTufStore;

/**
 * Tuf
 */
public class InMemoryTufStore implements MutableTufStore {
  private final MutableTufStore baseStore;

  public UpdateableTufStore(MutableTufStore baseStore) {
    this.baseStore = baseStore;
  }
}
