/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

public interface IFeatureDefinitionReferenceInstance<
    DEFINITION extends IDefinition,
    INSTANCE extends INamedInstance>
    extends INamedInstance {

  @Override
  DEFINITION getDefinition();

  @Override
  default boolean isInlineDefinition() {
    return false;
  }

  /**
   * Get the instance this definition is combined with.
   *
   * @return the instance or {@code null} if the definition is not inline
   */
  @Nullable
  default INSTANCE getInlineInstance() {
    return null;
  }

  @Override
  default String getEffectiveFormalName() {
    String result = getFormalName();
    return result == null ? getDefinition().getEffectiveFormalName() : result;
  }

  @Override
  default MarkupLine getEffectiveDescription() {
    MarkupLine result = getDescription();
    return result == null ? getDefinition().getEffectiveDescription() : result;
  }

  @Override
  @NonNull
  default String getEffectiveName() {
    String result = getUseName();
    if (result == null) {
      // fall back to the definition
      IDefinition def = getDefinition();
      result = def.getEffectiveName();
    }
    return result;
  }

  @Override
  @Nullable
  default Integer getEffectiveIndex() {
    Integer result = getUseIndex();
    if (result == null) {
      // fall back to the definition
      IDefinition def = getDefinition();
      result = def.getEffectiveIndex();
    }
    return result;
  }

  /**
   * The resolved default value, which allows an instance to override a
   * definition's default value.
   *
   * @return the default value or {@code null} if not defined on either the
   *         instance or definition
   */
  @Override
  @Nullable
  default Object getEffectiveDefaultValue() {
    Object retval = getDefaultValue();
    if (retval == null) {
      retval = getDefinition().getDefaultValue();
    }
    return retval;
  }
}
