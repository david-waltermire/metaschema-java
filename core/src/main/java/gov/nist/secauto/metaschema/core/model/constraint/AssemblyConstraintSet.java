/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.constraint;

import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;

import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.locks.Lock;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Represents a container of rules constraining the effective model of a
 * Metaschema assembly data instance.
 */
public class AssemblyConstraintSet
    extends ValueConstraintSet
    implements IModelConstrained {

  @NonNull
  private final List<IIndexConstraint> indexConstraints = new LinkedList<>();
  @NonNull
  private final List<IUniqueConstraint> uniqueConstraints = new LinkedList<>();
  @NonNull
  private final List<ICardinalityConstraint> cardinalityConstraints = new LinkedList<>();

  /**
   * Construct a new constraint set.
   *
   * @param source
   *          information about the resource the constraints were loaded from
   */
  public AssemblyConstraintSet(@NonNull ISource source) {
    super(source);
  }

  @Override
  public List<IIndexConstraint> getIndexConstraints() {
    Lock readLock = getLock().readLock();
    readLock.lock();
    try {
      return CollectionUtil.unmodifiableList(indexConstraints);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public List<IUniqueConstraint> getUniqueConstraints() {
    Lock readLock = getLock().readLock();
    readLock.lock();
    try {
      return CollectionUtil.unmodifiableList(uniqueConstraints);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public List<ICardinalityConstraint> getHasCardinalityConstraints() {
    Lock readLock = getLock().readLock();
    readLock.lock();
    try {
      return CollectionUtil.unmodifiableList(cardinalityConstraints);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public final void addConstraint(@NonNull IIndexConstraint constraint) {
    Lock writeLock = getLock().writeLock();
    writeLock.lock();
    try {
      getConstraintsInternal().add(constraint);
      indexConstraints.add(constraint);
    } finally {
      writeLock.unlock();
    }
  }

  @Override
  public final void addConstraint(@NonNull IUniqueConstraint constraint) {
    Lock writeLock = getLock().writeLock();
    writeLock.lock();
    try {
      getConstraintsInternal().add(constraint);
      uniqueConstraints.add(constraint);
    } finally {
      writeLock.unlock();
    }
  }

  @Override
  public final void addConstraint(@NonNull ICardinalityConstraint constraint) {
    Lock writeLock = getLock().writeLock();
    writeLock.lock();
    try {
      getConstraintsInternal().add(constraint);
      cardinalityConstraints.add(constraint);
    } finally {
      writeLock.unlock();
    }
  }
}
