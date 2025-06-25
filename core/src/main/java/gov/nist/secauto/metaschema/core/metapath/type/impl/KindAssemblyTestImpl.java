/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.metapath.item.node.IAssemblyNodeItem;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Tests that that a given item is an {@link IAssemblyNodeItem} with the
 * provided node and type name.
 */
public class KindAssemblyTestImpl
    extends AbstractDefinitionTest<IAssemblyNodeItem> {
  /**
   * Construct a new test.
   *
   * @param instanceName
   *          the name of the node
   * @param typeName
   *          the expected definition name to check against
   * @param staticContext
   *          used to resolve the definition name
   */
  public KindAssemblyTestImpl(
      @Nullable IEnhancedQName instanceName,
      @Nullable String typeName,
      @NonNull StaticContext staticContext) {
    super(instanceName, typeName, staticContext);
  }

  @Override
  protected String getTestName() {
    return "assembly";
  }

  @Override
  public Class<IAssemblyNodeItem> getItemClass() {
    return IAssemblyNodeItem.class;
  }

  @Override
  protected boolean matchesType(IAssemblyNodeItem item) {
    String typeName = getTypeName();
    return typeName == null
        || DynamicTypeSupport.derivesFrom(item, typeName, getTestStaticContext());
  }
}
