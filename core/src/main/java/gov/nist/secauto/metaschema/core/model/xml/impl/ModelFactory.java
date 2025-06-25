/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.xml.impl;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression;
import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.constraint.AbstractConstraintBuilder;
import gov.nist.secauto.metaschema.core.model.constraint.AbstractKeyConstraintBuilder;
import gov.nist.secauto.metaschema.core.model.constraint.ConstraintInitializationException;
import gov.nist.secauto.metaschema.core.model.constraint.IAllowedValue;
import gov.nist.secauto.metaschema.core.model.constraint.IAllowedValuesConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.ICardinalityConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraint.Level;
import gov.nist.secauto.metaschema.core.model.constraint.IExpectConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IIndexConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IIndexHasKeyConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IKeyField;
import gov.nist.secauto.metaschema.core.model.constraint.ILet;
import gov.nist.secauto.metaschema.core.model.constraint.IMatchesConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IUniqueConstraint;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.AllowedValueType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.AllowedValuesType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.ConstraintLetType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.ConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.ExpectConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.IndexHasKeyConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.KeyConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.MatchesConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.PropertyType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.RemarksType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.TargetedAllowedValuesConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.TargetedExpectConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.TargetedHasCardinalityConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.TargetedIndexConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.TargetedIndexHasKeyConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.TargetedKeyConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.TargetedMatchesConstraintType;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Produces Metaschema module data objects from XML-based XMLBeans data
 * bindings.
 */
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.GodClass" })
public final class ModelFactory {
  private ModelFactory() {
    // disable
  }

  @NonNull
  private static IMetapathExpression metapath(@Nullable String target, @NonNull ISource source) {
    return target == null
        ? IConstraint.defaultTarget()
        : IMetapathExpression.lazyCompile(target, source.getStaticContext());
  }

  @NonNull
  private static Level level(@Nullable Level level) {
    return level == null ? IConstraint.defaultLevel() : level;
  }

  @NonNull
  private static MarkupMultiline remarks(@NonNull RemarksType remarks) {
    return MarkupStringConverter.toMarkupString(remarks);
  }

  /**
   * Parse the properties.
   *
   * @param properties
   *          the XmlBeans property representation to parse
   * @return the properties as a mapping of name to values
   */
  @SuppressWarnings("null")
  @NonNull
  public static Map<IAttributable.Key, Set<String>> toProperties(
      @NonNull List<PropertyType> properties) {
    return properties.stream()
        .map(prop -> {
          String name = prop.getName();
          String namespace = prop.isSetNamespace() ? prop.getNamespace() : IAttributable.DEFAULT_PROPERY_NAMESPACE;
          IAttributable.Key key = IAttributable.key(name, namespace);
          String value = prop.getValue();

          return Map.entry(key, value);
        })
        .collect(Collectors.groupingBy(Map.Entry<IAttributable.Key, String>::getKey,
            Collectors.mapping(Map.Entry<IAttributable.Key, String>::getValue, Collectors.toSet())));
  }

  /**
   * Parse the allowed values.
   *
   * @param properties
   *          the XmlBeans allowed values representation to parse
   * @return the allowed values as a mapping of name to value object
   */
  @NonNull
  private static Map<String, IAllowedValue> toAllowedValues(
      @NonNull AllowedValuesType xmlObject,
      @NonNull ISource source) {
    Map<String, IAllowedValue> allowedValues // NOPMD - intentional
        = new LinkedHashMap<>(xmlObject.sizeOfEnumArray());
    for (AllowedValueType xmlEnum : xmlObject.getEnumList()) {
      String value = xmlEnum.getValue();
      if (value == null) {
        throw new ConstraintInitializationException(
            String.format("Null value found in allowed value enumeration in '%s': %s",
                source.getLocationHint(),
                xmlObject.xmlText()));
      }

      IAllowedValue allowedValue = IAllowedValue.of(
          value,
          MarkupStringConverter.toMarkupString(xmlEnum),
          xmlEnum.getDeprecated());
      allowedValues.put(allowedValue.getValue(), allowedValue);
    }
    return CollectionUtil.unmodifiableMap(allowedValues);
  }

  /**
   * Parse the constraint XMLBeans representation.
   *
   * @param xmlObject
   *          the XmlObject representing the constraint
   * @param source
   *          the descriptor for the resource containing the constraint
   * @return the parsed constraint object
   */
  @NonNull
  public static IAllowedValuesConstraint newAllowedValuesConstraint(
      @NonNull TargetedAllowedValuesConstraintType xmlObject,
      @NonNull ISource source) {
    return newAllowedValuesConstraint(xmlObject, metapath(xmlObject.getTarget(), source), source);
  }

  /**
   * Parse the constraint XMLBeans representation.
   *
   * @param xmlObject
   *          the XmlObject representing the constraint
   * @param source
   *          the descriptor for the resource containing the constraint
   * @return the parsed constraint object
   */
  @NonNull
  public static IAllowedValuesConstraint newAllowedValuesConstraint(
      @NonNull AllowedValuesType xmlObject,
      @NonNull ISource source) {
    return newAllowedValuesConstraint(xmlObject, IConstraint.defaultTarget(), source);
  }

  @NonNull
  private static IAllowedValuesConstraint newAllowedValuesConstraint(
      @NonNull AllowedValuesType xmlObject,
      @NonNull IMetapathExpression target,
      @NonNull ISource source) {

    IAllowedValuesConstraint.Builder builder = IAllowedValuesConstraint.builder();

    applyToBuilder(xmlObject, target, source, builder);

    if (xmlObject.isSetRemarks()) {
      builder.remarks(remarks(ObjectUtils.notNull(xmlObject.getRemarks())));
    }

    builder.allowedValues(toAllowedValues(xmlObject, source));
    if (xmlObject.isSetAllowOther()) {
      builder.allowsOther(xmlObject.getAllowOther());
    }
    if (xmlObject.isSetExtensible()) {
      builder.extensible(ObjectUtils.notNull(xmlObject.getExtensible()));
    }

    return builder.build();
  }

  @NonNull
  private static <T extends AbstractConstraintBuilder<T, ?>> T applyToBuilder(
      @NonNull ConstraintType xmlObject,
      @NonNull IMetapathExpression target,
      @NonNull ISource source,
      @NonNull T builder) {

    if (xmlObject.isSetId()) {
      builder.identifier(ObjectUtils.notNull(xmlObject.getId()));
    }
    builder.target(target);
    builder.source(source);
    builder.level(level(xmlObject.getLevel()));
    return builder;
  }

  /**
   * Parse the constraint XMLBeans representation.
   *
   * @param xmlObject
   *          the XmlObject representing the constraint
   * @param source
   *          the descriptor for the resource containing the constraint
   * @return the parsed constraint object
   */
  @NonNull
  public static IMatchesConstraint newMatchesConstraint(
      @NonNull TargetedMatchesConstraintType xmlObject,
      @NonNull ISource source) {
    return newMatchesConstraint(xmlObject, metapath(xmlObject.getTarget(), source), source);
  }

  /**
   * Parse the constraint XMLBeans representation.
   *
   * @param xmlConstraint
   *          the XmlObject representing the constraint
   * @param source
   *          the descriptor for the resource containing the constraint
   * @return the parsed constraint object
   */
  @NonNull
  public static IMatchesConstraint newMatchesConstraint(
      @NonNull MatchesConstraintType xmlConstraint,
      @NonNull ISource source) {
    return newMatchesConstraint(xmlConstraint, IConstraint.defaultTarget(), source);
  }

  @NonNull
  private static IMatchesConstraint newMatchesConstraint(
      @NonNull MatchesConstraintType xmlObject,
      @NonNull IMetapathExpression target,
      @NonNull ISource source) {
    IMatchesConstraint.Builder builder = IMatchesConstraint.builder();

    applyToBuilder(xmlObject, target, source, builder);

    if (xmlObject.isSetMessage()) {
      builder.message(ObjectUtils.notNull(xmlObject.getMessage()));
    }

    if (xmlObject.isSetRemarks()) {
      builder.remarks(remarks(ObjectUtils.notNull(xmlObject.getRemarks())));
    }

    if (xmlObject.isSetRegex()) {
      builder.regex(ObjectUtils.notNull(xmlObject.getRegex()));
    }
    if (xmlObject.isSetDatatype()) {
      builder.datatype(ObjectUtils.notNull(xmlObject.getDatatype()));
    }

    return builder.build();
  }

  private static void buildKeyFields(
      @NonNull KeyConstraintType xmlObject,
      @NonNull AbstractKeyConstraintBuilder<?, ?> builder,
      @NonNull ISource source) {
    for (KeyConstraintType.KeyField xmlKeyField : xmlObject.getKeyFieldList()) {
      IKeyField keyField = IKeyField.of(
          metapath(ObjectUtils.requireNonNull(xmlKeyField.getTarget()), source),
          xmlKeyField.isSetPattern() ? xmlKeyField.getPattern() : null,
          xmlKeyField.isSetRemarks() ? remarks(ObjectUtils.notNull(xmlKeyField.getRemarks())) : null);
      builder.keyField(keyField);
    }
  }

  /**
   * Parse the constraint XMLBeans representation.
   *
   * @param xmlObject
   *          the XmlObject representing the constraint
   * @param source
   *          the descriptor for the resource containing the constraint
   * @return the parsed constraint object
   */
  @NonNull
  public static IUniqueConstraint newUniqueConstraint(
      @NonNull TargetedKeyConstraintType xmlObject,
      @NonNull ISource source) {
    IUniqueConstraint.Builder builder = IUniqueConstraint.builder();

    applyToBuilder(xmlObject, metapath(xmlObject.getTarget(), source), source, builder);

    if (xmlObject.isSetMessage()) {
      builder.message(ObjectUtils.notNull(xmlObject.getMessage()));
    }

    if (xmlObject.isSetRemarks()) {
      builder.remarks(remarks(ObjectUtils.notNull(xmlObject.getRemarks())));
    }

    buildKeyFields(xmlObject, builder, source);

    return builder.build();
  }

  /**
   * Parse the constraint XMLBeans representation.
   *
   * @param xmlObject
   *          the XmlObject representing the constraint
   * @param source
   *          the descriptor for the resource containing the constraint
   * @return the parsed constraint object
   */
  @NonNull
  public static IIndexConstraint newIndexConstraint(
      @NonNull TargetedIndexConstraintType xmlObject,
      @NonNull ISource source) {
    IIndexConstraint.Builder builder = IIndexConstraint.builder(ObjectUtils.requireNonNull(xmlObject.getName()));

    applyToBuilder(xmlObject, metapath(xmlObject.getTarget(), source), source, builder);

    if (xmlObject.isSetMessage()) {
      builder.message(ObjectUtils.notNull(xmlObject.getMessage()));
    }

    if (xmlObject.isSetRemarks()) {
      builder.remarks(remarks(ObjectUtils.notNull(xmlObject.getRemarks())));
    }

    buildKeyFields(xmlObject, builder, source);

    return builder.build();
  }

  /**
   * Parse the constraint XMLBeans representation.
   *
   * @param xmlObject
   *          the XmlObject representing the constraint
   * @param source
   *          the descriptor for the resource containing the constraint
   * @return the parsed constraint object
   */
  @NonNull
  public static IIndexHasKeyConstraint newIndexHasKeyConstraint(
      @NonNull TargetedIndexHasKeyConstraintType xmlObject,
      @NonNull ISource source) {
    return newIndexHasKeyConstraint(xmlObject, metapath(xmlObject.getTarget(), source), source);
  }

  /**
   * Parse the constraint XMLBeans representation.
   *
   * @param xmlObject
   *          the XmlObject representing the constraint
   * @param source
   *          the descriptor for the resource containing the constraint
   * @return the parsed constraint object
   */
  @NonNull
  public static IIndexHasKeyConstraint newIndexHasKeyConstraint(
      @NonNull IndexHasKeyConstraintType xmlObject,
      @NonNull ISource source) {
    return newIndexHasKeyConstraint(xmlObject, IConstraint.defaultTarget(), source);
  }

  @NonNull
  private static IIndexHasKeyConstraint newIndexHasKeyConstraint(
      @NonNull IndexHasKeyConstraintType xmlObject,
      @NonNull IMetapathExpression target,
      @NonNull ISource source) {
    IIndexHasKeyConstraint.Builder builder
        = IIndexHasKeyConstraint.builder(ObjectUtils.requireNonNull(xmlObject.getName()));

    applyToBuilder(xmlObject, target, source, builder);

    if (xmlObject.isSetMessage()) {
      builder.message(ObjectUtils.notNull(xmlObject.getMessage()));
    }

    if (xmlObject.isSetRemarks()) {
      builder.remarks(remarks(ObjectUtils.notNull(xmlObject.getRemarks())));
    }

    buildKeyFields(xmlObject, builder, source);

    return builder.build();
  }

  /**
   * Parse the constraint XMLBeans representation.
   *
   * @param xmlObject
   *          the XmlObject representing the constraint
   * @param source
   *          the descriptor for the resource containing the constraint
   * @return the parsed constraint object
   */
  @NonNull
  public static IExpectConstraint newExpectConstraint(
      @NonNull TargetedExpectConstraintType xmlObject,
      @NonNull ISource source) {
    return newExpectConstraint(xmlObject, metapath(xmlObject.getTarget(), source), source);
  }

  /**
   * Parse the constraint XMLBeans representation.
   *
   * @param xmlObject
   *          the XmlObject representing the constraint
   * @param source
   *          the descriptor for the resource containing the constraint
   * @return the parsed constraint object
   */
  @NonNull
  public static IExpectConstraint newExpectConstraint(
      @NonNull ExpectConstraintType xmlObject,
      @NonNull ISource source) {
    return newExpectConstraint(xmlObject, IConstraint.defaultTarget(), source);
  }

  @NonNull
  private static IExpectConstraint newExpectConstraint(
      @NonNull ExpectConstraintType xmlObject,
      @NonNull IMetapathExpression target,
      @NonNull ISource source) {

    IExpectConstraint.Builder builder = IExpectConstraint.builder();

    applyToBuilder(xmlObject, target, source, builder);

    if (xmlObject.isSetMessage()) {
      builder.message(ObjectUtils.notNull(xmlObject.getMessage()));
    }

    if (xmlObject.isSetRemarks()) {
      builder.remarks(remarks(ObjectUtils.notNull(xmlObject.getRemarks())));
    }

    builder.test(
        IMetapathExpression.lazyCompile(
            ObjectUtils.requireNonNull(xmlObject.getTest()),
            source.getStaticContext()));

    return builder.build();
  }

  /**
   * Parse the constraint XMLBeans representation.
   *
   * @param xmlObject
   *          the XmlObject representing the constraint
   * @param source
   *          the descriptor for the resource containing the constraint
   * @return the parsed constraint object
   */
  @NonNull
  public static ICardinalityConstraint newCardinalityConstraint(
      @NonNull TargetedHasCardinalityConstraintType xmlObject,
      @NonNull ISource source) {

    ICardinalityConstraint.Builder builder = ICardinalityConstraint.builder();

    applyToBuilder(xmlObject, metapath(xmlObject.getTarget(), source), source, builder);

    if (xmlObject.isSetMessage()) {
      builder.message(ObjectUtils.notNull(xmlObject.getMessage()));
    }

    if (xmlObject.isSetRemarks()) {
      builder.remarks(remarks(ObjectUtils.notNull(xmlObject.getRemarks())));
    }

    if (xmlObject.isSetMinOccurs()) {
      builder.minOccurs(xmlObject.getMinOccurs().intValueExact());
    }

    if (xmlObject.isSetMaxOccurs()) {
      builder.maxOccurs(xmlObject.getMaxOccurs().intValueExact());
    }

    return builder.build();
  }

  /**
   * Generate a new Let expression by parsing the provided XMLBeans object.
   *
   * @param xmlObject
   *          the XmlObject representing the constraint
   * @param source
   *          the descriptor for the resource containing the constraint
   * @return the original let statement with the same name or {@code null}
   */
  @NonNull
  public static ILet newLet(
      @NonNull ConstraintLetType xmlObject,
      @NonNull ISource source) {
    StaticContext staticContext = source.getStaticContext();
    return ILet.of(
        staticContext.parseVariableName(ObjectUtils.requireNonNull(xmlObject.getVar())),
        IMetapathExpression.lazyCompile(ObjectUtils.notNull(xmlObject.getExpression()), staticContext),
        source,
        xmlObject.isSetRemarks()
            ? remarks(ObjectUtils.notNull(xmlObject.getRemarks()))
            : null);
  }
}
