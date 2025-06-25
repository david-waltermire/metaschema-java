/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.metapath.item.node.IFieldNodeItem;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Tests that that a given item is an {@link IFieldNodeItem} with the provided
 * node and type name.
 */
public class KindFieldTestImpl
    extends AbstractDefinitionTest<IFieldNodeItem> {

  /**
   * Construct a new test.
   *
   * @param instanceName
   *          the name of the node
   * @param typeName
   *          the expected definition or atomic type name to check against
   * @param staticContext
   *          used to resolve definition names and lookup atomic type names
   */
  public KindFieldTestImpl(
      @Nullable IEnhancedQName instanceName,
      @Nullable String typeName,
      @NonNull StaticContext staticContext) {
    super(instanceName, typeName, staticContext);
  }

  @Override
  protected String getTestName() {
    return "field";
  }

  @Override
  public Class<IFieldNodeItem> getItemClass() {
    return IFieldNodeItem.class;
  }

  @Override
  protected boolean matchesType(IFieldNodeItem item) {
    String typeName = getTypeName();
    return typeName == null
        || DynamicTypeSupport.derivesFrom(item, typeName, getTestStaticContext());
  }
}
