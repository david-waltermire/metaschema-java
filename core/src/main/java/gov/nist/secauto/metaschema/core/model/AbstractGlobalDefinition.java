/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * A base class for definitions defined globally within a Metaschema module.
 *
 * @param <MODULE>
 *          the Java type of the containing module
 * @param <INSTANCE>
 *          the expected Java type of an instance of this definition
 */
public abstract class AbstractGlobalDefinition<MODULE extends IModule, INSTANCE extends INamedInstance>
    implements IDefinition {
  @NonNull
  private final MODULE module;
  @NonNull
  private final Lazy<IEnhancedQName> qname;
  @NonNull
  private final Lazy<IEnhancedQName> definitionQName;

  /**
   * Construct a new global definition.
   *
   * @param module
   *          the parent module containing this instance
   * @param initializer
   *          the callback used to generate qualified names
   */
  protected AbstractGlobalDefinition(@NonNull MODULE module, @NonNull NameInitializer initializer) {
    this.module = module;
    this.qname = ObjectUtils.notNull(Lazy.of(() -> initializer.apply(getEffectiveName())));
    this.definitionQName = ObjectUtils.notNull(Lazy.of(() -> initializer.apply(getName())));
  }

  @Override
  public final MODULE getContainingModule() {
    return module;
  }

  @Override
  public ISource getSource() {
    return getContainingModule().getSource();
  }

  @SuppressWarnings("null")
  @Override
  public final IEnhancedQName getQName() {
    return qname.get();
  }

  @SuppressWarnings("null")
  @Override
  public final IEnhancedQName getDefinitionQName() {
    return definitionQName.get();
  }

  @Override
  public boolean isInline() {
    // never inline
    return false;
  }

  @Override
  public final INSTANCE getInlineInstance() {
    // never inline
    return null;
  }

  /**
   * Provides a callback for generating a qualified name from a name.
   */
  @FunctionalInterface
  public interface NameInitializer {
    /**
     * Produce a qualified name by parsing the provided name.
     *
     * @param name
     *          the name to parse
     * @return the qualified name for the provided name
     */
    @NonNull
    IEnhancedQName apply(@NonNull String name);
  }
}
