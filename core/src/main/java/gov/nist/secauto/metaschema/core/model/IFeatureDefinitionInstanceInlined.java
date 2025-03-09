/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Locale;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * A trait indicating that the implementation is a localized definition that is
 * declared in-line as an instance.
 *
 * @param <DEFINITION>
 *          the associated definition Java type
 * @param <INSTANCE>
 *          the associated instance Java type
 */
public interface IFeatureDefinitionInstanceInlined<
    DEFINITION extends IDefinition,
    INSTANCE extends INamedInstance>
    extends IDefinition, INamedInstance {

  @Override
  default IEnhancedQName getDefinitionQName() {
    return getReferencedDefinitionQName();
  }

  @Override
  default DEFINITION getDefinition() {
    return ObjectUtils.asType(this);
  }

  @Override
  default boolean isInlineDefinition() {
    return true;
  }

  @Override
  default boolean isInline() {
    // has to be inline
    return true;
  }

  @Override
  @NonNull
  default INSTANCE getInlineInstance() {
    return ObjectUtils.asType(this);
  }

  @Override
  default String getEffectiveFormalName() {
    return getFormalName();
  }

  @Override
  default MarkupLine getEffectiveDescription() {
    return getDescription();
  }

  @Override
  default String getEffectiveName() {
    // don't use use-name
    return getName();
  }

  @Override
  default Integer getEffectiveIndex() {
    return getIndex();
  }

  @Override
  @Nullable
  default Object getEffectiveDefaultValue() {
    // This is an inline instance that is both a definition and an instance. Don't
    // delegate to the definition, since this would be redundant.
    return getDefaultValue();
  }

  @Override
  default ISource getSource() {
    return getContainingModule().getSource();
  }

  /**
   * Generates a "coordinate" string for the provided inline definition instance.
   *
   * A coordinate consists of the element's:
   * <ul>
   * <li>containing Metaschema module's short name
   * <li>model type
   * <li>definition name
   * <li>hash code
   * </ul>
   *
   * @return the coordinate
   */
  @SuppressWarnings("null")
  @Override
  default String toCoordinates() {
    IModule module = getContainingModule();
    return String.format("%s-inline-definition:%s:%s/%s@%d",
        getModelType().toString().toLowerCase(Locale.ROOT),
        module.getShortName(),
        getContainingDefinition().getName(),
        getName(),
        hashCode());
  }
}
