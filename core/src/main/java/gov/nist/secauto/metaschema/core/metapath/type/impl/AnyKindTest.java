/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.metapath.item.node.IAssemblyNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDocumentNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IFieldNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IFlagNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IModuleNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.metapath.type.IKindTest;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An item type that applies to all items of a specific node-based type.
 *
 * @param <T>
 *          the Java type of the node-based item supported by the implementation
 */
@SuppressWarnings("PMD.TestClassWithoutTestCases")
public final class AnyKindTest<T extends INodeItem>
    extends AbstractItemType<T>
    implements IKindTest<T> {
  /**
   * Matches to all nodes.
   */
  @NonNull
  public static final IKindTest<INodeItem> ANY_NODE = new AnyKindTest<>(
      "node",
      INodeItem.class,
      "");
  /**
   * Matches all module nodes.
   */
  @NonNull
  public static final IKindTest<IModuleNodeItem> ANY_MODULE = new AnyKindTest<>(
      "module",
      IModuleNodeItem.class,
      "");
  /**
   * Matches all document nodes.
   */
  @NonNull
  public static final IKindTest<IDocumentNodeItem> ANY_DOCUMENT = new AnyKindTest<>(
      "document-node",
      IDocumentNodeItem.class,
      "");
  /**
   * Matches all assembly nodes.
   */
  @NonNull
  public static final IKindTest<IAssemblyNodeItem> ANY_ASSEMBLY = new AnyKindTest<>(
      "assembly",
      IAssemblyNodeItem.class,
      "");
  /**
   * Matches all field nodes.
   */
  @NonNull
  public static final IKindTest<IFieldNodeItem> ANY_FIELD = new AnyKindTest<>(
      "field",
      IFieldNodeItem.class,
      "");
  /**
   * Matches all flag nodes.
   */
  @NonNull
  public static final IKindTest<IFlagNodeItem> ANY_FLAG = new AnyKindTest<>(
      "flag",
      IFlagNodeItem.class,
      "");

  @NonNull
  private final String testName;
  @NonNull
  private final String test;

  private AnyKindTest(
      @NonNull String testName,
      @NonNull Class<T> itemClass,
      @NonNull String test) {
    super(itemClass);
    this.testName = testName;
    this.test = test;
  }

  @Override
  protected String generateSignature() {
    return ObjectUtils.notNull(new StringBuilder()
        .append(testName)
        .append('(')
        .append(test)
        .append(')')
        .toString());
  }
}
