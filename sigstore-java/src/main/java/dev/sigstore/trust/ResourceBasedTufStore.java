package dev.sigstore.trust;

import dev.sigstore.tuf.MutableTufStore;

/**
 * Loads TUF data from classpath resources.
 * TODO: it probably needs to verify the checksum of the loaded root.json.
 */
public class ResourceBasedTufStore implements MutableTufStore {
  private final String prefix;

  public ResourceBasedTufStore(String prefix) {
    this.prefix = prefix;
  }
}
