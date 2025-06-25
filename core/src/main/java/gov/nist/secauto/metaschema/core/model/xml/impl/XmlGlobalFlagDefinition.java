/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.xml.impl;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.model.AbstractGlobalFlagDefinition;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.IFlagInstance;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.constraint.IValueConstrained;
import gov.nist.secauto.metaschema.core.model.constraint.ValueConstraintSet;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.GlobalFlagDefinitionType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.UseNameType;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Map;
import java.util.Set;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

class XmlGlobalFlagDefinition
    extends AbstractGlobalFlagDefinition<XmlModule, IFlagInstance> {
  @NonNull
  private final GlobalFlagDefinitionType xmlFlag;
  @Nullable
  private final Object defaultValue;
  private final Lazy<IValueConstrained> constraints;

  /**
   * Constructs a new Metaschema flag definition from an XML representation bound
   * to Java objects.
   *
   * @param xmlFlag
   *          the XML representation bound to Java objects
   * @param module
   *          the containing Metaschema module
   */
  public XmlGlobalFlagDefinition(
      @NonNull GlobalFlagDefinitionType xmlFlag,
      @NonNull XmlModule module) {
    super(module);
    this.xmlFlag = xmlFlag;
    Object defaultValue = null;
    if (xmlFlag.isSetDefault()) {
      defaultValue = getJavaTypeAdapter().parse(ObjectUtils.requireNonNull(xmlFlag.getDefault()));
    }
    this.defaultValue = defaultValue;
    ISource source = module.getSource();
    this.constraints = Lazy.of(() -> {
      IValueConstrained retval = new ValueConstraintSet(source);
      if (getXmlFlag().isSetConstraint()) {
        ConstraintXmlSupport.parse(retval, ObjectUtils.notNull(getXmlFlag().getConstraint()), source);
      }
      return retval;
    });
  }

  /**
   * Used to generate the instances for the constraints in a lazy fashion when the
   * constraints are first accessed.
   *
   * @return the constraints instance
   */
  @SuppressWarnings("null")
  @Override
  public IValueConstrained getConstraintSupport() {
    return constraints.get();
  }

  @Override
  public Object getDefaultValue() {
    return defaultValue;
  }

  // ----------------------------------------
  // - Start annotation driven code - CPD-OFF
  // ----------------------------------------

  /**
   * Get the underlying XML representation.
   *
   * @return the underlying XML data
   */
  protected final GlobalFlagDefinitionType getXmlFlag() {
    return xmlFlag;
  }

  @SuppressWarnings("null")
  @Override
  public ModuleScope getModuleScope() {
    return getXmlFlag().isSetScope() ? getXmlFlag().getScope() : DEFAULT_MODULE_SCOPE;
  }

  @SuppressWarnings("null")
  @Override
  public String getName() {
    return getXmlFlag().getName();
  }

  @Override
  public Integer getIndex() {
    return getXmlFlag().isSetIndex() ? getXmlFlag().getIndex().intValue() : null;
  }

  @Override
  public String getUseName() {
    return getXmlFlag().isSetUseName() ? getXmlFlag().getUseName().getStringValue() : null;
  }

  @Override
  public Integer getUseIndex() {
    Integer retval = null;
    if (getXmlFlag().isSetUseName()) {
      UseNameType useName = getXmlFlag().getUseName();
      if (useName.isSetIndex()) {
        retval = useName.getIndex().intValue();
      }
    }
    return retval;
  }

  @Override
  public String getFormalName() {
    return getXmlFlag().isSetFormalName() ? getXmlFlag().getFormalName() : null;
  }

  @SuppressWarnings("null")
  @Override
  public MarkupLine getDescription() {
    return getXmlFlag().isSetDescription() ? MarkupStringConverter.toMarkupString(getXmlFlag().getDescription()) : null;
  }

  @Override
  public Map<IAttributable.Key, Set<String>> getProperties() {
    return ModelFactory.toProperties(CollectionUtil.listOrEmpty(getXmlFlag().getPropList()));
  }

  @SuppressWarnings("null")
  @Override
  public final IDataTypeAdapter<?> getJavaTypeAdapter() {
    return getXmlFlag().isSetAsType() ? getXmlFlag().getAsType() : MetaschemaDataTypeProvider.DEFAULT_DATA_TYPE;
  }

  @SuppressWarnings("null")
  @Override
  public MarkupMultiline getRemarks() {
    return getXmlFlag().isSetRemarks() ? MarkupStringConverter.toMarkupString(getXmlFlag().getRemarks()) : null;
  }

  // --------------------------------------
  // - End annotation driven code - CPD-ON
  // --------------------------------------
}
