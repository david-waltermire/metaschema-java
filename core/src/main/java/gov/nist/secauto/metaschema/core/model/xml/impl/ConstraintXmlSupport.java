/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.xml.impl;

import gov.nist.secauto.metaschema.core.MetaschemaConstants;
import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.constraint.IAllowedValue;
import gov.nist.secauto.metaschema.core.model.constraint.IAllowedValuesConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.ICardinalityConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraintVisitor;
import gov.nist.secauto.metaschema.core.model.constraint.IExpectConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IIndexConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IIndexHasKeyConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IKeyConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IKeyField;
import gov.nist.secauto.metaschema.core.model.constraint.ILet;
import gov.nist.secauto.metaschema.core.model.constraint.IMatchesConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IModelConstrained;
import gov.nist.secauto.metaschema.core.model.constraint.IUniqueConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IValueConstrained;
import gov.nist.secauto.metaschema.core.model.xml.XmlModuleConstants;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.AllowedValueType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.AllowedValuesType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.ConstraintLetType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.ConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.DefineAssemblyConstraintsType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.DefineFieldConstraintsType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.DefineFlagConstraintsType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.ExpectConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.IndexHasKeyConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.KeyConstraintType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.KeyConstraintType.KeyField;
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
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlObject;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Supports parsing constraints defined in an XMLBeans-based XML instance.
 */
@SuppressWarnings("PMD.CouplingBetweenObjects")
public final class ConstraintXmlSupport {
  @NonNull
  private static final XmlObjectParser<IValueConstrained> FLAG_PARSER
      = new XmlObjectParser<>(ObjectUtils.notNull(
          Map.ofEntries(
              Map.entry(XmlModuleConstants.ALLOWED_VALUES_CONSTRAINT_QNAME, ConstraintXmlSupport::handleAllowedValues),
              Map.entry(XmlModuleConstants.INDEX_HAS_KEY_CONSTRAINT_QNAME, ConstraintXmlSupport::handleIndexHasKey),
              Map.entry(XmlModuleConstants.MATCHES_CONSTRAINT_QNAME, ConstraintXmlSupport::handleMatches),
              Map.entry(XmlModuleConstants.EXPECT_CONSTRAINT_QNAME, ConstraintXmlSupport::handleExpect)))) {

        @SuppressWarnings("synthetic-access")
        @Override
        protected Handler<IValueConstrained> identifyHandler(XmlCursor cursor, XmlObject obj) {
          Handler<IValueConstrained> retval;
          if (obj instanceof AllowedValuesType) {
            retval = ConstraintXmlSupport::handleAllowedValues;
          } else if (obj instanceof IndexHasKeyConstraintType) {
            retval = ConstraintXmlSupport::handleIndexHasKey;
          } else if (obj instanceof MatchesConstraintType) {
            retval = ConstraintXmlSupport::handleMatches;
          } else if (obj instanceof ExpectConstraintType) {
            retval = ConstraintXmlSupport::handleExpect;
          } else {
            retval = super.identifyHandler(cursor, obj);
          }
          return retval;
        }
      };

  @NonNull
  private static final XmlObjectParser<IValueConstrained> FIELD_PARSER
      = new XmlObjectParser<>(ObjectUtils.notNull(Map.ofEntries(
          Map.entry(XmlModuleConstants.ALLOWED_VALUES_CONSTRAINT_QNAME,
              ConstraintXmlSupport::handleScopedAllowedValues),
          Map.entry(XmlModuleConstants.INDEX_HAS_KEY_CONSTRAINT_QNAME,
              ConstraintXmlSupport::handleScopedIndexHasKey),
          Map.entry(XmlModuleConstants.MATCHES_CONSTRAINT_QNAME, ConstraintXmlSupport::handleScopedMatches),
          Map.entry(XmlModuleConstants.EXPECT_CONSTRAINT_QNAME, ConstraintXmlSupport::handleScopedExpect)))) {

        @SuppressWarnings("synthetic-access")
        @Override
        protected Handler<IValueConstrained> identifyHandler(XmlCursor cursor, XmlObject obj) {
          Handler<IValueConstrained> retval;
          if (obj instanceof TargetedAllowedValuesConstraintType) {
            retval = ConstraintXmlSupport::handleScopedAllowedValues;
          } else if (obj instanceof TargetedIndexHasKeyConstraintType) {
            retval = ConstraintXmlSupport::handleScopedIndexHasKey;
          } else if (obj instanceof TargetedMatchesConstraintType) {
            retval = ConstraintXmlSupport::handleScopedMatches;
          } else if (obj instanceof TargetedExpectConstraintType) {
            retval = ConstraintXmlSupport::handleScopedExpect;
          } else {
            retval = super.identifyHandler(cursor, obj);
          }
          return retval;
        }
      };

  @NonNull
  private static final XmlObjectParser<IModelConstrained> ASSEMBLY_PARSER
      = new XmlObjectParser<>(ObjectUtils.notNull(Map.ofEntries(
          Map.entry(XmlModuleConstants.ALLOWED_VALUES_CONSTRAINT_QNAME,
              ConstraintXmlSupport::handleScopedAllowedValues),
          Map.entry(XmlModuleConstants.INDEX_HAS_KEY_CONSTRAINT_QNAME,
              ConstraintXmlSupport::handleScopedIndexHasKey),
          Map.entry(XmlModuleConstants.MATCHES_CONSTRAINT_QNAME, ConstraintXmlSupport::handleScopedMatches),
          Map.entry(XmlModuleConstants.EXPECT_CONSTRAINT_QNAME, ConstraintXmlSupport::handleScopedExpect),
          Map.entry(XmlModuleConstants.INDEX_CONSTRAINT_QNAME, ConstraintXmlSupport::handleScopedIndex),
          Map.entry(XmlModuleConstants.IS_UNIQUE_CONSTRAINT_QNAME, ConstraintXmlSupport::handleScopedIsUnique),
          Map.entry(XmlModuleConstants.HAS_CARDINALITY_CONSTRAINT_QNAME,
              ConstraintXmlSupport::handleScopedHasCardinality)))) {

        @SuppressWarnings("synthetic-access")
        @Override
        protected Handler<IModelConstrained> identifyHandler(XmlCursor cursor, XmlObject obj) {
          Handler<IModelConstrained> retval;
          if (obj instanceof TargetedAllowedValuesConstraintType) {
            retval = ConstraintXmlSupport::handleScopedAllowedValues;
          } else if (obj instanceof TargetedIndexHasKeyConstraintType) {
            retval = ConstraintXmlSupport::handleScopedIndexHasKey;
          } else if (obj instanceof TargetedMatchesConstraintType) {
            retval = ConstraintXmlSupport::handleScopedMatches;
          } else if (obj instanceof TargetedExpectConstraintType) {
            retval = ConstraintXmlSupport::handleScopedExpect;
          } else if (obj instanceof TargetedIndexConstraintType) {
            retval = ConstraintXmlSupport::handleScopedIndex;
          } else if (obj instanceof TargetedKeyConstraintType) {
            retval = ConstraintXmlSupport::handleScopedIsUnique;
          } else if (obj instanceof TargetedHasCardinalityConstraintType) {
            retval = ConstraintXmlSupport::handleScopedHasCardinality;
          } else {
            retval = super.identifyHandler(cursor, obj);
          }
          return retval;
        }

      };

  private static void parseLets(
      @NonNull List<ConstraintLetType> letList,
      @NonNull IValueConstrained constraints,
      @NonNull ISource source) {
    for (ConstraintLetType xmlLet : letList) {
      assert xmlLet != null;
      ILet let = ModelFactory.newLet(xmlLet, source);
      constraints.addLetExpression(let);
    }
  }

  /**
   * Parse a set of constraints from the provided XMLBeans {@code xmlObject} and
   * apply them to the provided {@code constraints}.
   *
   * @param constraints
   *          the constraint collection to add the parsed constraints to
   * @param xmlObject
   *          the XMLBeans instance
   * @param source
   *          information about the source of the constraints
   */
  public static void parse(
      @NonNull IValueConstrained constraints,
      @NonNull DefineFlagConstraintsType xmlObject,
      @NonNull ISource source) {
    parseLets(ObjectUtils.notNull(xmlObject.getLetList()), constraints, source);
    parse(
        FLAG_PARSER,
        constraints,
        (XmlObject) xmlObject,
        source);
  }

  /**
   * Parse a set of constraints from the provided XMLBeans {@code xmlObject} and
   * apply them to the provided {@code constraints}.
   *
   * @param constraints
   *          the constraint collection to add the parsed constraints to
   * @param xmlObject
   *          the XMLBeans instance
   * @param source
   *          information about the source of the constraints
   */
  public static void parse(
      @NonNull IValueConstrained constraints,
      @NonNull DefineFieldConstraintsType xmlObject,
      @NonNull ISource source) {
    parseLets(ObjectUtils.notNull(xmlObject.getLetList()), constraints, source);
    parse(
        FIELD_PARSER,
        constraints,
        (XmlObject) xmlObject,
        source);
  }

  /**
   * Parse a set of constraints from the provided XMLBeans {@code xmlObject} and
   * apply them to the provided {@code constraints}.
   *
   * @param constraints
   *          the constraint collection to add the parsed constraints to
   * @param xmlObject
   *          the XMLBeans instance
   * @param source
   *          information about the source of the constraints
   */
  public static void parse(
      @NonNull IModelConstrained constraints,
      @NonNull DefineAssemblyConstraintsType xmlObject,
      @NonNull ISource source) {
    parseLets(ObjectUtils.notNull(xmlObject.getLetList()), constraints, source);
    parse(
        ASSEMBLY_PARSER,
        constraints,
        (XmlObject) xmlObject,
        source);
  }

  private static <T> void parse(
      @NonNull XmlObjectParser<T> parser,
      @NonNull T constraints,
      @NonNull XmlObject xmlObject,
      @NonNull ISource source) {
    parser.parse(source, xmlObject, constraints);
  }

  private static void handleAllowedValues(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      IValueConstrained state) {
    IAllowedValuesConstraint constraint = ModelFactory.newAllowedValuesConstraint(
        (AllowedValuesType) obj,
        source);
    state.addConstraint(constraint);
  }

  private static void handleScopedAllowedValues(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      IValueConstrained state) {
    IAllowedValuesConstraint constraint = ModelFactory.newAllowedValuesConstraint(
        (TargetedAllowedValuesConstraintType) obj,
        source);
    state.addConstraint(constraint);
  }

  private static void handleMatches(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      IValueConstrained state) {
    IMatchesConstraint constraint = ModelFactory.newMatchesConstraint(
        (MatchesConstraintType) obj,
        source);
    state.addConstraint(constraint);
  }

  private static void handleScopedMatches(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      IValueConstrained state) {
    IMatchesConstraint constraint = ModelFactory.newMatchesConstraint(
        (TargetedMatchesConstraintType) obj,
        source);
    state.addConstraint(constraint);
  }

  private static void handleIndexHasKey(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      IValueConstrained state) {
    IIndexHasKeyConstraint constraint = ModelFactory.newIndexHasKeyConstraint(
        (IndexHasKeyConstraintType) obj,
        source);
    state.addConstraint(constraint);
  }

  private static void handleScopedIndexHasKey(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      IValueConstrained state) {
    IIndexHasKeyConstraint constraint = ModelFactory.newIndexHasKeyConstraint(
        (TargetedIndexHasKeyConstraintType) obj,
        source);
    state.addConstraint(constraint);
  }

  private static void handleExpect(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      IValueConstrained state) {
    IExpectConstraint constraint = ModelFactory.newExpectConstraint(
        (ExpectConstraintType) obj,
        source);
    state.addConstraint(constraint);
  }

  private static void handleScopedExpect(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      IValueConstrained state) {
    IExpectConstraint constraint = ModelFactory.newExpectConstraint(
        (TargetedExpectConstraintType) obj,
        source);
    state.addConstraint(constraint);
  }

  private static void handleScopedIndex(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      IModelConstrained state) {
    IIndexConstraint constraint = ModelFactory.newIndexConstraint(
        (TargetedIndexConstraintType) obj,
        source);
    state.addConstraint(constraint);
  }

  private static void handleScopedIsUnique(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      IModelConstrained state) {
    IUniqueConstraint constraint = ModelFactory.newUniqueConstraint(
        (TargetedKeyConstraintType) obj,
        source);
    state.addConstraint(constraint);
  }

  private static void handleScopedHasCardinality(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      IModelConstrained state) {
    ICardinalityConstraint constraint = ModelFactory.newCardinalityConstraint(
        (TargetedHasCardinalityConstraintType) obj,
        source);
    state.addConstraint(constraint);
  }

  private ConstraintXmlSupport() {
    // disable construction
  }

  @SuppressWarnings("unused")
  private static final class XmlbeanGeneratingVisitor
      implements IConstraintVisitor<DefineAssemblyConstraintsType, Void> {

    private static void applyCommonValues(@NonNull IConstraint constraint, @NonNull ConstraintType bean) {
      MarkupLine description = constraint.getDescription();
      if (description != null) {
        bean.setDescription(MarkupStringConverter.toMarkupLineDatatype(description));
      }
      String formalName = constraint.getFormalName();
      if (formalName != null) {
        bean.setFormalName(formalName);
      }

      String id = constraint.getId();
      if (id != null) {
        bean.setId(constraint.getId());
      }

      IConstraint.Level level = constraint.getLevel();
      if (!IConstraint.defaultLevel().equals(level)) {
        bean.setLevel(level);
      }

      for (Map.Entry<IAttributable.Key, Set<String>> entry : constraint.getProperties().entrySet()) {
        IAttributable.Key key = entry.getKey();
        Set<String> values = entry.getValue();
        for (String value : values) {
          PropertyType prop = bean.addNewProp();
          prop.setName(key.getName());

          String namespace = key.getNamespace();
          if (!IAttributable.DEFAULT_PROPERY_NAMESPACE.equals(namespace)) {
            prop.setNamespace(namespace);
          }
          prop.setValue(value);
        }
      }
    }

    @Override
    public Void visitAllowedValues(IAllowedValuesConstraint constraint, DefineAssemblyConstraintsType state) {
      TargetedAllowedValuesConstraintType bean = state.addNewAllowedValues();
      assert bean != null;
      applyCommonValues(constraint, bean);

      if (Boolean.compare(IAllowedValuesConstraint.ALLOW_OTHER_DEFAULT, constraint.isAllowedOther()) != 0) {
        bean.setAllowOther(constraint.isAllowedOther());
      }
      bean.setTarget(constraint.getTarget().getPath());
      bean.setExtensible(constraint.getExtensible());

      for (Map.Entry<String, ? extends IAllowedValue> entry : constraint.getAllowedValues().entrySet()) {
        String value = entry.getKey();
        IAllowedValue allowedValue = entry.getValue();

        assert allowedValue != null;
        assert value.equals(allowedValue.getValue());

        MarkupLine description = allowedValue.getDescription();
        AllowedValueType enumType = bean.addNewEnum();
        enumType.setValue(value);

        XmlbeansMarkupWriter.visit(description, MetaschemaConstants.METASCHEMA_NAMESPACE, enumType);
      }

      MarkupMultiline remarks = constraint.getRemarks();
      if (remarks != null) {
        RemarksType remarksType = bean.addNewRemarks();
        assert remarksType != null;
        XmlbeansMarkupWriter.visit(remarks, MetaschemaConstants.METASCHEMA_NAMESPACE, remarksType);
      }
      return null;
    }

    @Override
    public Void visitCardinalityConstraint(ICardinalityConstraint constraint, DefineAssemblyConstraintsType state) {
      TargetedHasCardinalityConstraintType bean = state.addNewHasCardinality();
      assert bean != null;
      applyCommonValues(constraint, bean);

      Integer minOccurs = constraint.getMinOccurs();
      if (minOccurs != null) {
        bean.setMinOccurs(BigInteger.valueOf(minOccurs));
      }

      Integer maxOccurs = constraint.getMaxOccurs();
      if (maxOccurs != null) {
        bean.setMaxOccurs(BigInteger.valueOf(maxOccurs));
      }

      MarkupMultiline remarks = constraint.getRemarks();
      if (remarks != null) {
        RemarksType remarksType = bean.addNewRemarks();
        assert remarksType != null;
        XmlbeansMarkupWriter.visit(remarks, MetaschemaConstants.METASCHEMA_NAMESPACE, remarksType);
      }
      return null;
    }

    @Override
    public Void visitExpectConstraint(IExpectConstraint constraint, DefineAssemblyConstraintsType state) {
      TargetedExpectConstraintType bean = state.addNewExpect();
      assert bean != null;
      applyCommonValues(constraint, bean);

      bean.setTest(constraint.getTest().getPath());

      String message = constraint.getMessage();
      if (message != null) {
        bean.setMessage(message);
      }

      MarkupMultiline remarks = constraint.getRemarks();
      if (remarks != null) {
        RemarksType remarksType = bean.addNewRemarks();
        assert remarksType != null;
        XmlbeansMarkupWriter.visit(remarks, MetaschemaConstants.METASCHEMA_NAMESPACE, remarksType);
      }
      return null;
    }

    @Override
    public Void visitMatchesConstraint(IMatchesConstraint constraint, DefineAssemblyConstraintsType state) {
      TargetedMatchesConstraintType bean = state.addNewMatches();
      assert bean != null;
      applyCommonValues(constraint, bean);

      Pattern pattern = constraint.getPattern();
      if (pattern != null) {
        bean.setRegex(pattern);
      }

      IDataTypeAdapter<?> dataType = constraint.getDataType();
      if (dataType != null) {
        bean.setDatatype(dataType);
      }

      MarkupMultiline remarks = constraint.getRemarks();
      if (remarks != null) {
        RemarksType remarksType = bean.addNewRemarks();
        assert remarksType != null;
        XmlbeansMarkupWriter.visit(remarks, MetaschemaConstants.METASCHEMA_NAMESPACE, remarksType);
      }
      return null;
    }

    private static void applyKeyFields(@NonNull IKeyConstraint constraint, @NonNull KeyConstraintType bean) {
      for (IKeyField keyField : constraint.getKeyFields()) {
        KeyField keyFieldBean = bean.addNewKeyField();
        assert keyField != null;
        assert keyFieldBean != null;
        applyKeyField(keyField, keyFieldBean);
      }
    }

    private static void applyKeyField(@NonNull IKeyField keyField, @NonNull KeyField bean) {
      Pattern pattern = keyField.getPattern();
      if (pattern != null) {
        bean.setPattern(pattern);
      }

      bean.setTarget(keyField.getTarget().getPath());

      MarkupMultiline remarks = keyField.getRemarks();
      if (remarks != null) {
        RemarksType remarksType = bean.addNewRemarks();
        assert remarksType != null;
        XmlbeansMarkupWriter.visit(remarks, MetaschemaConstants.METASCHEMA_NAMESPACE, remarksType);
      }
    }

    @Override
    public Void visitIndexConstraint(IIndexConstraint constraint, DefineAssemblyConstraintsType state) {
      TargetedIndexConstraintType bean = state.addNewIndex();
      assert bean != null;
      applyCommonValues(constraint, bean);
      applyKeyFields(constraint, bean);

      bean.setName(constraint.getName());

      MarkupMultiline remarks = constraint.getRemarks();
      if (remarks != null) {
        RemarksType remarksType = bean.addNewRemarks();
        assert remarksType != null;
        XmlbeansMarkupWriter.visit(remarks, MetaschemaConstants.METASCHEMA_NAMESPACE, remarksType);
      }
      return null;
    }

    @Override
    public Void visitIndexHasKeyConstraint(IIndexHasKeyConstraint constraint, DefineAssemblyConstraintsType state) {
      TargetedIndexHasKeyConstraintType bean = state.addNewIndexHasKey();
      assert bean != null;
      applyCommonValues(constraint, bean);
      applyKeyFields(constraint, bean);

      bean.setName(constraint.getIndexName());

      MarkupMultiline remarks = constraint.getRemarks();
      if (remarks != null) {
        RemarksType remarksType = bean.addNewRemarks();
        assert remarksType != null;
        XmlbeansMarkupWriter.visit(remarks, MetaschemaConstants.METASCHEMA_NAMESPACE, remarksType);
      }
      return null;
    }

    @Override
    public Void visitUniqueConstraint(IUniqueConstraint constraint, DefineAssemblyConstraintsType state) {
      TargetedIndexHasKeyConstraintType bean = state.addNewIndexHasKey();
      assert bean != null;
      applyCommonValues(constraint, bean);
      applyKeyFields(constraint, bean);

      MarkupMultiline remarks = constraint.getRemarks();
      if (remarks != null) {
        RemarksType remarksType = bean.addNewRemarks();
        assert remarksType != null;
        XmlbeansMarkupWriter.visit(remarks, MetaschemaConstants.METASCHEMA_NAMESPACE, remarksType);
      }
      return null;
    }
  }
}
