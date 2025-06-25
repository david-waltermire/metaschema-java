/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.xml.impl;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.model.AbstractInlineFlagDefinition;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.IFlagDefinition;
import gov.nist.secauto.metaschema.core.model.IFlagInstance;
import gov.nist.secauto.metaschema.core.model.IModelDefinition;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.constraint.IValueConstrained;
import gov.nist.secauto.metaschema.core.model.constraint.ValueConstraintSet;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.InlineFlagDefinitionType;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Map;
import java.util.Set;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

class XmlInlineFlagDefinition
    extends AbstractInlineFlagDefinition<IModelDefinition, IFlagDefinition, IFlagInstance> {

  @NonNull
  private final InlineFlagDefinitionType xmlFlag;
  @Nullable
  private final Object defaultValue;
  @NonNull
  private final Lazy<IValueConstrained> constraints;

  /**
   * Constructs a new Metaschema flag definition from an XML representation bound
   * to Java objects.
   *
   * @param xmlObject
   *          the XML representation bound to Java objects
   * @param parent
   *          the parent definition, which must be a definition type that can
   *          contain flags.
   */
  @SuppressWarnings("PMD.NullAssignment")
  public XmlInlineFlagDefinition(@NonNull InlineFlagDefinitionType xmlObject, @NonNull IModelDefinition parent) {
    super(parent);
    this.xmlFlag = xmlObject;
    this.defaultValue = xmlObject.isSetDefault()
        ? getJavaTypeAdapter().parse(ObjectUtils.requireNonNull(xmlObject.getDefault()))
        : null;

    ISource source = parent.getContainingModule().getSource();

    this.constraints = ObjectUtils.notNull(Lazy.of(() -> {
      IValueConstrained retval = new ValueConstraintSet(source);
      if (getXmlObject().isSetConstraint()) {
        ConstraintXmlSupport.parse(retval, ObjectUtils.notNull(getXmlObject().getConstraint()), source);
      }
      return retval;
    }));
  }

  /**
   * Used to generate the instances for the constraints in a lazy fashion when the
   * constraints are first accessed.
   */
  @Override
  public IValueConstrained getConstraintSupport() {
    return ObjectUtils.notNull(constraints.get());
  }

  @Override
  public Object getDefaultValue() {
    return defaultValue;
  }

  // ----------------------------------------
  // - Start XmlBeans driven code - CPD-OFF -
  // ----------------------------------------

  /**
   * Get the underlying XML model.
   *
   * @return the XML model
   */
  protected final InlineFlagDefinitionType getXmlObject() {
    return xmlFlag;
  }

  @SuppressWarnings("null")
  @Override
  public final IDataTypeAdapter<?> getJavaTypeAdapter() {
    return getXmlObject().isSetAsType() ? getXmlObject().getAsType() : MetaschemaDataTypeProvider.DEFAULT_DATA_TYPE;
  }

  @Override
  public String getFormalName() {
    return getXmlObject().isSetFormalName() ? getXmlObject().getFormalName() : null;
  }

  @SuppressWarnings("null")
  @Override
  public MarkupLine getDescription() {
    return getXmlObject().isSetDescription() ? MarkupStringConverter.toMarkupString(getXmlObject().getDescription())
        : null;
  }

  @Override
  public Map<IAttributable.Key, Set<String>> getProperties() {
    return ModelFactory.toProperties(CollectionUtil.listOrEmpty(getXmlObject().getPropList()));
  }

  @SuppressWarnings("null")
  @Override
  public String getName() {
    return getXmlObject().getName();
  }

  @Override
  public Integer getIndex() {
    return getXmlObject().isSetIndex() ? getXmlObject().getIndex().intValue() : null;
  }

  @Override
  public boolean isRequired() {
    return getXmlObject().isSetRequired() ? getXmlObject().getRequired() : DEFAULT_FLAG_REQUIRED;
  }

  @SuppressWarnings("null")
  @Override
  public MarkupMultiline getRemarks() {
    return getXmlObject().isSetRemarks() ? MarkupStringConverter.toMarkupString(getXmlObject().getRemarks()) : null;
  }

  // -------------------------------------
  // - End XmlBeans driven code - CPD-ON -
  // -------------------------------------
}
