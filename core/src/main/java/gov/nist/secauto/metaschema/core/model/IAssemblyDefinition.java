/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import gov.nist.secauto.metaschema.core.MetaschemaConstants;
import gov.nist.secauto.metaschema.core.model.constraint.IFeatureModelConstrained;
import gov.nist.secauto.metaschema.core.model.util.ModuleUtils;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

public interface IAssemblyDefinition
    extends IModelDefinition, IContainerModelAssembly, IAssembly, IFeatureModelConstrained {
  IEnhancedQName MODEL_QNAME = IEnhancedQName.of(MetaschemaConstants.METASCHEMA_NAMESPACE, "model");

  /**
   * Check if the assembly is a top-level root assembly.
   *
   * @return {@code true} if the assembly is a top-level root, or {@code false}
   *         otherwise
   */
  default boolean isRoot() {
    // not a root by default
    return false;
  }

  /**
   * Get the root name if this assembly is a top-level root.
   *
   * @return the root name if this assembly is a top-level root, or {@code null}
   *         otherwise
   */
  @Nullable
  default String getRootName() {
    // not a root by default
    return null;
  }

  /**
   * Get the root index to use for binary data, if this assembly is a top-level
   * root.
   *
   * @return the root index if provided and this assembly is a top-level root, or
   *         {@code null} otherwise
   */
  @Nullable
  default Integer getRootIndex() {
    // not a root by default
    return null;
  }

  /**
   * Get the XML qualified name to use in XML as the root element.
   *
   * @return the root XML qualified name if this assembly is a top-level root, or
   *         {@code null} otherwise
   */
  default IEnhancedQName getRootQName() {
    IEnhancedQName retval = null;
    String rootName = getRootName();
    if (rootName != null) {
      retval = ModuleUtils.parseModelName(getContainingModule(), rootName);
    }
    return retval;
  }

  /**
   * Get the name used for the associated property in JSON/YAML.
   *
   * @return the root JSON property name if this assembly is a top-level root, or
   *         {@code null} otherwise
   */
  default String getRootJsonName() {
    return getRootName();
  }

  @Override
  default boolean isInline() {
    // not inline by default
    return false;
  }

  @Override
  default IAssemblyInstance getInlineInstance() {
    // not inline by default
    return null;
  }

  @Override
  default IAssemblyDefinition getOwningDefinition() {
    return this;
  }
  //
  // @Override
  // default IAssemblyNodeItem getNodeItem() {
  // return null;
  // }

  @Override
  default boolean hasChildren() {
    return IModelDefinition.super.hasChildren() || IContainerModelAssembly.super.hasChildren();
  }

  /**
   * A visitor callback.
   *
   * @param <CONTEXT>
   *          the type of the context parameter
   * @param <RESULT>
   *          the type of the visitor result
   * @param visitor
   *          the calling visitor
   * @param context
   *          a parameter used to pass contextual information between visitors
   * @return the visitor result
   */
  @Override
  default <CONTEXT, RESULT> RESULT accept(@NonNull IModelElementVisitor<CONTEXT, RESULT> visitor, CONTEXT context) {
    return visitor.visitAssemblyDefinition(this, context);
  }
}
