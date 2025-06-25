/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.impl;

import gov.nist.secauto.metaschema.core.datatype.DataTypeService;
import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.constraint.AbstractConfigurableMessageConstraintBuilder;
import gov.nist.secauto.metaschema.core.model.constraint.AbstractConstraintBuilder;
import gov.nist.secauto.metaschema.core.model.constraint.AbstractKeyConstraintBuilder;
import gov.nist.secauto.metaschema.core.model.constraint.IAllowedValue;
import gov.nist.secauto.metaschema.core.model.constraint.IAllowedValuesConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.ICardinalityConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IExpectConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IIndexConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IIndexHasKeyConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IKeyField;
import gov.nist.secauto.metaschema.core.model.constraint.ILet;
import gov.nist.secauto.metaschema.core.model.constraint.IMatchesConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IUniqueConstraint;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.model.annotations.AllowedValue;
import gov.nist.secauto.metaschema.databind.model.annotations.AllowedValues;
import gov.nist.secauto.metaschema.databind.model.annotations.Expect;
import gov.nist.secauto.metaschema.databind.model.annotations.HasCardinality;
import gov.nist.secauto.metaschema.databind.model.annotations.Index;
import gov.nist.secauto.metaschema.databind.model.annotations.IndexHasKey;
import gov.nist.secauto.metaschema.databind.model.annotations.IsUnique;
import gov.nist.secauto.metaschema.databind.model.annotations.KeyField;
import gov.nist.secauto.metaschema.databind.model.annotations.Let;
import gov.nist.secauto.metaschema.databind.model.annotations.Matches;
import gov.nist.secauto.metaschema.databind.model.annotations.ModelUtil;
import gov.nist.secauto.metaschema.databind.model.annotations.NullJavaTypeAdapter;
import gov.nist.secauto.metaschema.databind.model.annotations.Property;

import java.util.Arrays;
import java.util.regex.Pattern;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

@SuppressWarnings("PMD.CouplingBetweenObjects")
final class ConstraintFactory {
  private ConstraintFactory() {
    // disable
  }

  static MarkupMultiline toRemarks(@NonNull String remarks) {
    return remarks.isBlank() ? null : MarkupMultiline.fromMarkdown(remarks);
  }

  @NonNull
  static IMetapathExpression metapath(
      @NonNull String metapath,
      @NonNull ISource source) {
    return metapath.isBlank()
        ? IConstraint.defaultTarget()
        : IMetapathExpression.lazyCompile(metapath, source.getStaticContext());
  }

  @NonNull
  static <T extends AbstractConstraintBuilder<T, ?>> T applyId(@NonNull T builder, @NonNull String id) {
    if (!id.isBlank()) {
      builder.identifier(id);
    }
    return builder;
  }

  @NonNull
  static <T extends AbstractConstraintBuilder<T, ?>> T applyFormalName(@NonNull T builder, @NonNull String name) {
    if (!name.isBlank()) {
      builder.formalName(name);
    }
    return builder;
  }

  @NonNull
  static <T extends AbstractConstraintBuilder<T, ?>> T applyDescription(@NonNull T builder, @NonNull String value) {
    if (!value.isBlank()) {
      builder.description(MarkupLine.fromMarkdown(value));
    }
    return builder;
  }

  @NonNull
  static <T extends AbstractConstraintBuilder<T, ?>> T applyTarget(
      @NonNull T builder,
      @NonNull IMetapathExpression expression) {
    builder.target(expression);
    return builder;
  }

  @NonNull
  static <T extends AbstractConstraintBuilder<T, ?>> T applyProperties(
      @NonNull T builder,
      @Nullable Property... properties) {
    if (properties != null) {
      Arrays.stream(properties)
          .map(ModelUtil::toPropertyEntry)
          .forEachOrdered(entry -> builder.property(
              ObjectUtils.notNull(entry.getKey()),
              ObjectUtils.notNull(entry.getValue())));
    }
    return builder;
  }

  static <T extends AbstractConfigurableMessageConstraintBuilder<T, ?>> T applyMessage(@NonNull T builder,
      @Nullable String message) {
    if (message != null && !message.isBlank()) {
      builder.message(message);
    }
    return builder;
  }

  static <T extends AbstractConstraintBuilder<T, ?>> T applyRemarks(@NonNull T builder, @NonNull String remarks) {
    if (!remarks.isBlank()) {
      builder.remarks(MarkupMultiline.fromMarkdown(remarks));
    }
    return builder;
  }

  @SuppressWarnings("PMD.NullAssignment")
  @NonNull
  static IAllowedValuesConstraint.Builder applyAllowedValues(
      @NonNull IAllowedValuesConstraint.Builder builder,
      @NonNull AllowedValues constraint) {
    for (AllowedValue value : constraint.values()) {
      String deprecatedVersion = value.deprecatedVersion();
      if (deprecatedVersion.isBlank()) {
        deprecatedVersion = null;
      }

      IAllowedValue allowedValue = IAllowedValue.of(
          value.value(),
          MarkupLine.fromMarkdown(value.description()),
          deprecatedVersion);
      builder.allowedValue(allowedValue);
    }
    return builder;
  }

  @Nullable
  static Pattern toPattern(@NonNull String pattern) {
    return pattern.isBlank() ? null : Pattern.compile(pattern);
  }

  @Nullable
  static String toMessage(@NonNull String message) {
    return message.isBlank() ? null : message;
  }

  @Nullable
  static IDataTypeAdapter<?> toDataType(@NonNull Class<? extends IDataTypeAdapter<?>> adapterClass) {
    return adapterClass.isAssignableFrom(NullJavaTypeAdapter.class) ? null
        : DataTypeService.instance().getDataTypeByAdapterClass(adapterClass);
  }

  @NonNull
  static IAllowedValuesConstraint newAllowedValuesConstraint(
      @NonNull AllowedValues constraint,
      @NonNull ISource source) {
    IAllowedValuesConstraint.Builder builder = IAllowedValuesConstraint.builder();
    applyId(builder, constraint.id());
    applyFormalName(builder, constraint.formalName());
    applyDescription(builder, constraint.description());
    builder
        .source(source)
        .level(constraint.level());
    applyTarget(builder, metapath(constraint.target(), source));
    applyProperties(builder, constraint.properties());
    applyRemarks(builder, constraint.remarks());

    applyAllowedValues(builder, constraint);
    builder.allowsOther(constraint.allowOthers());
    builder.extensible(constraint.extensible());

    return builder.build();
  }

  @NonNull
  static IMatchesConstraint newMatchesConstraint(Matches constraint, @NonNull ISource source) {
    IMatchesConstraint.Builder builder = IMatchesConstraint.builder();
    applyId(builder, constraint.id());
    applyFormalName(builder, constraint.formalName());
    applyDescription(builder, constraint.description());
    builder
        .source(source)
        .level(constraint.level());
    applyTarget(builder, metapath(constraint.target(), source));
    applyProperties(builder, constraint.properties());
    applyMessage(builder, constraint.message());
    applyRemarks(builder, constraint.remarks());

    Pattern pattern = toPattern(constraint.pattern());
    if (pattern != null) {
      builder.regex(pattern);
    }

    IDataTypeAdapter<?> dataType = toDataType(constraint.typeAdapter());
    if (dataType != null) {
      builder.datatype(dataType);
    }

    return builder.build();
  }

  @NonNull
  static <T extends AbstractKeyConstraintBuilder<T, ?>> T applyKeyFields(
      @NonNull T builder,
      @NonNull ISource source,
      @NonNull KeyField... keyFields) {
    for (KeyField keyField : keyFields) {
      IKeyField field = IKeyField.of(
          metapath(keyField.target(), source),
          toPattern(keyField.pattern()),
          toRemarks(keyField.remarks()));
      builder.keyField(field);
    }
    return builder;
  }

  @NonNull
  static IUniqueConstraint newUniqueConstraint(@NonNull IsUnique constraint, @NonNull ISource source) {
    IUniqueConstraint.Builder builder = IUniqueConstraint.builder();
    applyId(builder, constraint.id());
    applyFormalName(builder, constraint.formalName());
    applyDescription(builder, constraint.description());
    builder
        .source(source)
        .level(constraint.level());
    applyTarget(builder, metapath(constraint.target(), source));
    applyProperties(builder, constraint.properties());
    applyMessage(builder, constraint.message());
    applyRemarks(builder, constraint.remarks());

    applyKeyFields(builder, source, constraint.keyFields());

    return builder.build();
  }

  @NonNull
  static IIndexConstraint newIndexConstraint(@NonNull Index constraint, @NonNull ISource source) {
    IIndexConstraint.Builder builder = IIndexConstraint.builder(constraint.name());
    applyId(builder, constraint.id());
    applyFormalName(builder, constraint.formalName());
    applyDescription(builder, constraint.description());
    builder
        .source(source)
        .level(constraint.level());
    applyTarget(builder, metapath(constraint.target(), source));
    applyProperties(builder, constraint.properties());
    applyMessage(builder, constraint.message());
    applyRemarks(builder, constraint.remarks());

    applyKeyFields(builder, source, constraint.keyFields());

    return builder.build();
  }

  @NonNull
  static IIndexHasKeyConstraint newIndexHasKeyConstraint(
      @NonNull IndexHasKey constraint,
      @NonNull ISource source) {
    IIndexHasKeyConstraint.Builder builder = IIndexHasKeyConstraint.builder(constraint.indexName());
    applyId(builder, constraint.id());
    applyFormalName(builder, constraint.formalName());
    applyDescription(builder, constraint.description());
    builder
        .source(source)
        .level(constraint.level());
    applyTarget(builder, metapath(constraint.target(), source));
    applyProperties(builder, constraint.properties());
    applyMessage(builder, constraint.message());
    applyRemarks(builder, constraint.remarks());

    applyKeyFields(builder, source, constraint.keyFields());

    return builder.build();
  }

  @NonNull
  static IExpectConstraint newExpectConstraint(@NonNull Expect constraint, @NonNull ISource source) {
    IExpectConstraint.Builder builder = IExpectConstraint.builder();
    applyId(builder, constraint.id());
    applyFormalName(builder, constraint.formalName());
    applyDescription(builder, constraint.description());
    builder
        .source(source)
        .level(constraint.level());
    applyTarget(builder, metapath(constraint.target(), source));
    applyProperties(builder, constraint.properties());
    applyMessage(builder, constraint.message());
    applyRemarks(builder, constraint.remarks());

    builder.test(metapath(constraint.test(), source));

    return builder.build();
  }

  @Nullable
  static Integer toCardinality(int value) {
    return value < 0 ? null : value;
  }

  @NonNull
  static ICardinalityConstraint newCardinalityConstraint(@NonNull HasCardinality constraint,
      @NonNull ISource source) {
    ICardinalityConstraint.Builder builder = ICardinalityConstraint.builder();
    applyId(builder, constraint.id());
    applyFormalName(builder, constraint.formalName());
    applyDescription(builder, constraint.description());
    builder
        .source(source)
        .level(constraint.level());
    applyTarget(builder, metapath(constraint.target(), source));
    applyProperties(builder, constraint.properties());
    applyMessage(builder, constraint.message());
    applyRemarks(builder, constraint.remarks());

    Integer min = toCardinality(constraint.minOccurs());
    if (min != null) {
      builder.minOccurs(min);
    }
    Integer max = toCardinality(constraint.maxOccurs());
    if (max != null) {
      builder.maxOccurs(max);
    }

    return builder.build();
  }

  @NonNull
  static ILet newLetExpression(@NonNull Let annotation, @NonNull ISource source) {
    String remarkMarkdown = annotation.remarks();
    MarkupMultiline remarks = remarkMarkdown.isBlank()
        ? null
        : MarkupMultiline.fromMarkdown(remarkMarkdown);
    return ILet.of(
        source.getStaticContext().parseVariableName(annotation.name()),
        IMetapathExpression.lazyCompile(annotation.target(), source.getStaticContext()),
        source,
        remarks);
  }
}
