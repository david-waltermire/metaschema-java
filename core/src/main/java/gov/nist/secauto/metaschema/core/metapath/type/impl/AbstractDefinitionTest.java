/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDefinitionNodeItem;
import gov.nist.secauto.metaschema.core.metapath.type.AbstractItemTypeBase;
import gov.nist.secauto.metaschema.core.metapath.type.IKindTest;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * This abstract implementation supports kind tests based on node item that have
 * an underlying Metaschema definition.
 * <p>
 * This class uses late binding for the type name, to ensure that the same name
 * can be used to identify the name of the definition or the name of the atomic
 * type (in the case of a field or flag).
 *
 * @param <T>
 *          the Java type of the node-based item supported by the implementation
 */
public abstract class AbstractDefinitionTest<T extends IDefinitionNodeItem<?, ?>>
    extends AbstractItemTypeBase
    implements IKindTest<T> {
  /**
   * The qualified name of the node instance.
   */
  @Nullable
  private final IEnhancedQName instanceName;
  /**
   * The qualified name of the definition or atomic type.
   */
  @Nullable
  private final String typeName;
  @NonNull
  private final StaticContext testStaticContext;

  /**
   * Construct a new definition-based kind test.
   *
   * @param testName
   *          the name of the test
   * @param instanceName
   *          the name of the node item to test
   * @param typeName
   *          the name of the definition or atomic type to test
   * @param staticContext
   *          the static context in which the test was declared
   */
  protected AbstractDefinitionTest(
      @Nullable IEnhancedQName instanceName,
      @Nullable String typeName,
      @NonNull StaticContext staticContext) {
    this.instanceName = instanceName;
    this.typeName = typeName;
    this.testStaticContext = staticContext;
  }

  /**
   * Get the name identifying the type of test.
   *
   * @return the name
   */
  protected abstract String getTestName();

  /**
   * Get the qualified name of the node instance.
   *
   * @return the qualified name
   */
  @Nullable
  protected IEnhancedQName getInstanceName() {
    return instanceName;
  }

  /**
   * Get the qualified name of the definition or atomic type.
   *
   * @return the qualified name or {@code null} if this value should not be tested
   */
  @Nullable
  protected String getTypeName() {
    return typeName;
  }

  /**
   * Get the static context used to lookup names and types for the test.
   *
   * @return the static context
   */
  @NonNull
  protected StaticContext getTestStaticContext() {
    return testStaticContext;
  }

  @SuppressWarnings("unchecked")
  @Override
  public boolean isInstance(IItem item) {
    return item != null
        && IKindTest.super.isInstance(item)
        && matches((T) item);
  }

  private boolean matches(@NonNull T item) {
    return matchesInstance(item) && matchesType(item);
  }

  private boolean matchesInstance(@NonNull T item) {
    return instanceName == null || ObjectUtils.notNull(instanceName).equals(item.getQName());
  }

  /**
   * Perform the model type-specific checks.
   *
   * @param item
   *          the item to test
   * @return {@code true} if the item meets expectations, or {@code false}
   *         otherwise
   */
  protected abstract boolean matchesType(@NonNull T item);

  @Override
  protected String generateSignature() {

    StringBuilder signatureBuilder = new StringBuilder()
        .append(getTestName())
        .append('(');

    if (instanceName != null && typeName != null) {
      signatureBuilder
          .append(instanceName.toQName())
          .append(',')
          .append(typeName);
    } else if (instanceName != null) {
      signatureBuilder
          .append(instanceName.toQName());
    } else if (typeName != null) {
      signatureBuilder
          .append("*,")
          .append(typeName);
    }

    return ObjectUtils.notNull(signatureBuilder
        .append(')')
        .toString());
  }
}
