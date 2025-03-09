/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Provides a set of callbacks used when iterating over node items in a directed
 * graph.
 * <p>
 * The {@link AbstractModelElementVisitor} provides an abstract implementation
 * of this visitor pattern.
 *
 * @param <CONTEXT>
 *          the type of data to pass to each visited node
 * @param <RESULT>
 *          the type of result produced by visitation
 * @see AbstractModelElementVisitor
 */
public interface IModelElementVisitor<CONTEXT, RESULT> {
  /**
   * This callback is called when an {@link IFlagInstance} is visited.
   *
   * @param item
   *          the visited item
   * @param context
   *          provides contextual information for use by the visitor
   * @return the visitation result
   */
  RESULT visitFlagInstance(@NonNull IFlagInstance item, CONTEXT context);

  /**
   * This callback is called when an {@link IFieldInstanceAbsolute} is visited.
   *
   * @param item
   *          the visited item
   * @param context
   *          provides contextual information for use by the visitor
   * @return the visitation result
   */
  RESULT visitFieldInstance(@NonNull IFieldInstanceAbsolute item, CONTEXT context);

  /**
   * This callback is called when an {@link IFieldInstanceGrouped} is visited.
   *
   * @param item
   *          the visited item
   * @param context
   *          provides contextual information for use by the visitor
   * @return the visitation result
   */
  RESULT visitFieldInstance(@NonNull IFieldInstanceGrouped item, CONTEXT context);

  /**
   * This callback is called when an {@link IAssemblyInstanceAbsolute} is visited.
   *
   * @param item
   *          the visited item
   * @param context
   *          provides contextual information for use by the visitor
   * @return the visitation result
   */
  RESULT visitAssemblyInstance(@NonNull IAssemblyInstanceAbsolute item, CONTEXT context);

  /**
   * This callback is called when an {@link IAssemblyInstanceGrouped} is visited.
   *
   * @param item
   *          the visited item
   * @param context
   *          provides contextual information for use by the visitor
   * @return the visitation result
   */
  RESULT visitAssemblyInstance(@NonNull IAssemblyInstanceGrouped item, CONTEXT context);

  /**
   * This callback is called when an {@link IChoiceInstance} is visited.
   *
   * @param item
   *          the visited item
   * @param context
   *          provides contextual information for use by the visitor
   * @return the visitation result
   */
  RESULT visitChoiceInstance(@NonNull IChoiceInstance item, CONTEXT context);

  /**
   * This callback is called when an {@link IChoiceGroupInstance} is visited.
   *
   * @param item
   *          the visited item
   * @param context
   *          provides contextual information for use by the visitor
   * @return the visitation result
   */
  RESULT visitChoiceGroupInstance(@NonNull IChoiceGroupInstance item, CONTEXT context);

  /**
   * This callback is called when an {@link IFlagDefinition} is visited.
   *
   * @param item
   *          the visited item
   * @param context
   *          provides contextual information for use by the visitor
   * @return the visitation result
   */
  RESULT visitFlagDefinition(@NonNull IFlagDefinition item, CONTEXT context);

  /**
   * This callback is called when an {@link IFieldDefinition} is visited.
   *
   * @param item
   *          the visited item
   * @param context
   *          provides contextual information for use by the visitor
   * @return the visitation result
   */
  RESULT visitFieldDefinition(@NonNull IFieldDefinition item, CONTEXT context);

  /**
   * This callback is called when an {@link IAssemblyDefinition} is visited.
   *
   * @param item
   *          the visited item
   * @param context
   *          provides contextual information for use by the visitor
   * @return the visitation result
   */
  RESULT visitAssemblyDefinition(@NonNull IAssemblyDefinition item, CONTEXT context);
}
