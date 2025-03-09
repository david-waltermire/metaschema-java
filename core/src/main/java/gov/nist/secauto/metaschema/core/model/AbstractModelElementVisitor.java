/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import gov.nist.secauto.metaschema.core.metapath.item.node.AbstractNodeItemVisitor;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Provides a set of callbacks used when iterating over model elements in a
 * directed graph.
 * <p>
 * The {@link AbstractNodeItemVisitor} provides an abstract implementation of
 * this visitor pattern.
 *
 * @param <CONTEXT>
 *          the type of data to pass to each visited node
 * @param <RESULT>
 *          the type of result produced by visitation
 * @see AbstractModelElementVisitor
 */
public abstract class AbstractModelElementVisitor<CONTEXT, RESULT> implements IModelElementVisitor<CONTEXT, RESULT> {
  protected abstract RESULT defaultResult(@NonNull IModelElement element, CONTEXT context);

  @Override
  public RESULT visitFlagInstance(IFlagInstance item, CONTEXT context) {
    // do nothing
    return defaultResult(item, context);
  }

  @Override
  public RESULT visitFieldInstance(IFieldInstanceAbsolute item, CONTEXT context) {
    // do nothing
    return defaultResult(item, context);
  }

  @Override
  public RESULT visitFieldInstance(IFieldInstanceGrouped item, CONTEXT context) {
    // do nothing
    return defaultResult(item, context);
  }

  @Override
  public RESULT visitAssemblyInstance(IAssemblyInstanceAbsolute item, CONTEXT context) {
    // do nothing
    return defaultResult(item, context);
  }

  @Override
  public RESULT visitAssemblyInstance(IAssemblyInstanceGrouped item, CONTEXT context) {
    // do nothing
    return defaultResult(item, context);
  }

  @Override
  public RESULT visitChoiceInstance(IChoiceInstance item, CONTEXT context) {
    // do nothing
    return defaultResult(item, context);
  }

  @Override
  public RESULT visitChoiceGroupInstance(IChoiceGroupInstance item, CONTEXT context) {
    // do nothing
    return defaultResult(item, context);
  }

  @Override
  public RESULT visitFlagDefinition(IFlagDefinition item, CONTEXT context) {
    // do nothing
    return defaultResult(item, context);
  }

  @Override
  public RESULT visitFieldDefinition(IFieldDefinition item, CONTEXT context) {
    // do nothing
    return defaultResult(item, context);
  }

  @Override
  public RESULT visitAssemblyDefinition(IAssemblyDefinition item, CONTEXT context) {
    // do nothing
    return defaultResult(item, context);
  }
}
