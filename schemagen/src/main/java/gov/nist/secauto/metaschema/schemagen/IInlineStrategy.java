/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.schemagen;

import gov.nist.secauto.metaschema.core.configuration.IConfiguration;
import gov.nist.secauto.metaschema.core.model.IDefinition;

import edu.umd.cs.findbugs.annotations.NonNull;

@FunctionalInterface
public interface IInlineStrategy {
  @NonNull
  IInlineStrategy NONE_INLINE = (@NonNull IDefinition definition, @NonNull ModuleIndex metaschemaIndex) -> false;

  @NonNull
  IInlineStrategy DEFINED_AS_INLINE
      = (@NonNull IDefinition definition, @NonNull ModuleIndex metaschemaIndex) -> definition.isInline();

  @NonNull
  IInlineStrategy CHOICE_NOT_INLINE = new ChoiceNotInlineStrategy();

  @NonNull
  static IInlineStrategy newInlineStrategy(@NonNull IConfiguration<SchemaGenerationFeature<?>> configuration) {
    IInlineStrategy retval;
    if (configuration.isFeatureEnabled(SchemaGenerationFeature.INLINE_DEFINITIONS)) {
      if (configuration.isFeatureEnabled(SchemaGenerationFeature.INLINE_CHOICE_DEFINITIONS)) {
        retval = DEFINED_AS_INLINE;
      } else {
        retval = CHOICE_NOT_INLINE;
      }
    } else {
      retval = NONE_INLINE;
    }
    return retval;
  }

  boolean isInline(
      @NonNull IDefinition definition,
      @NonNull ModuleIndex metaschemaIndex);
}
