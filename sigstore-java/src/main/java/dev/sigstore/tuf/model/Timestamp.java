package dev.sigstore.tuf.model;

import org.immutables.gson.Gson;

public interface Timestamp extends SignedTufMeta<TufMeta>{

  @Override
  @Gson.Named("signed")
  SnapshotMeta getSignedMeta();
}
