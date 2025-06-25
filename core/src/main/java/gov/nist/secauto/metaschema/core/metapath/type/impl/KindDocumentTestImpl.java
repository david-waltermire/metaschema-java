/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IAssemblyNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDocumentNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IRootAssemblyNodeItem;
import gov.nist.secauto.metaschema.core.metapath.type.AbstractItemTypeBase;
import gov.nist.secauto.metaschema.core.metapath.type.IKindTest;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Tests that that a given item is an {@link IDocumentNodeItem} that has a root
 * node of the provided kind.
 */
public class KindDocumentTestImpl
    extends AbstractItemTypeBase
    implements IKindTest<IDocumentNodeItem> {
  private final IKindTest<IAssemblyNodeItem> assemblyTest;

  /**
   * Construct a new test.
   *
   * @param assemblyTest
   *          the root node test
   */
  public KindDocumentTestImpl(@NonNull IKindTest<IAssemblyNodeItem> assemblyTest) {
    this.assemblyTest = assemblyTest;
  }

  @Override
  public Class<IDocumentNodeItem> getItemClass() {
    return IDocumentNodeItem.class;
  }

  @Override
  public boolean isInstance(IItem item) {
    return item != null
        && IKindTest.super.isInstance(item)
        && assemblyMatches(ObjectUtils.asType(item));
  }

  private boolean assemblyMatches(@NonNull IDocumentNodeItem item) {
    IRootAssemblyNodeItem root = item.getRootAssemblyNodeItem();
    return assemblyTest == null || assemblyTest.isInstance(root);
  }

  @Override
  protected String generateSignature() {
    // build the signature
    return ObjectUtils.notNull(new StringBuilder()
        .append("document-node(")
        .append(assemblyTest.toSignature())
        .append(')')
        .toString());
  }
}
