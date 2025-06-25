/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.xml.impl;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.model.AbstractGlobalFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.IContainerFlagSupport;
import gov.nist.secauto.metaschema.core.model.IFieldInstance;
import gov.nist.secauto.metaschema.core.model.IFlagInstance;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.constraint.IValueConstrained;
import gov.nist.secauto.metaschema.core.model.constraint.ValueConstraintSet;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.GlobalFieldDefinitionType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.UseNameType;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Map;
import java.util.Set;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

class XmlGlobalFieldDefinition
    extends AbstractGlobalFieldDefinition<XmlModule, IFieldInstance, IFlagInstance> {
  @NonNull
  private final GlobalFieldDefinitionType xmlObject;
  @Nullable
  private final Object defaultValue;
  @NonNull
  private final Lazy<IContainerFlagSupport<IFlagInstance>> flagContainer;
  @NonNull
  private final Lazy<IValueConstrained> constraints;

  /**
   * Constructs a new Metaschema field definition from an XML representation bound
   * to Java objects.
   *
   * @param xmlObject
   *          the XML representation bound to Java objects
   * @param module
   *          the containing Metaschema module
   */
  public XmlGlobalFieldDefinition(@NonNull GlobalFieldDefinitionType xmlObject, @NonNull XmlModule module) {
    super(module);
    this.xmlObject = xmlObject;
    Object defaultValue = null;
    if (xmlObject.isSetDefault()) {
      defaultValue = getJavaTypeAdapter().parse(ObjectUtils.requireNonNull(xmlObject.getDefault()));
    }
    this.defaultValue = defaultValue;
    this.flagContainer = ObjectUtils.notNull(Lazy.of(() -> XmlFlagContainerSupport.newInstance(xmlObject, this)));
    ISource source = module.getSource();
    this.constraints = ObjectUtils.notNull(Lazy.of(() -> {
      IValueConstrained retval = new ValueConstraintSet(source);
      if (getXmlObject().isSetConstraint()) {
        ConstraintXmlSupport.parse(retval, ObjectUtils.notNull(getXmlObject().getConstraint()), source);
      }
      return retval;
    }));
  }

  /**
   * Lazy initialize the flag instances associated with this definition.
   *
   * @return the flag container
   */
  @SuppressWarnings("null")
  @Override
  public IContainerFlagSupport<IFlagInstance> getFlagContainer() {
    return flagContainer.get();
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
  // - Start XmlBeans driven code - CPD-OFF -
  // ----------------------------------------

  /**
   * Get the underlying XML data.
   *
   * @return the underlying XML data
   */
  @NonNull
  protected final GlobalFieldDefinitionType getXmlObject() {
    return xmlObject;
  }

  @SuppressWarnings({ "null" })
  @Override
  public String getName() {
    return getXmlObject().getName();
  }

  @Override
  public Integer getIndex() {
    return getXmlObject().isSetIndex() ? getXmlObject().getIndex().intValue() : null;
  }

  @Override
  public String getUseName() {
    return getXmlObject().isSetUseName() ? getXmlObject().getUseName().getStringValue() : null;
  }

  @Override
  public Integer getUseIndex() {
    Integer retval = null;
    if (getXmlObject().isSetUseName()) {
      UseNameType useName = getXmlObject().getUseName();
      if (useName.isSetIndex()) {
        retval = useName.getIndex().intValue();
      }
    }
    return retval;
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
  public final IDataTypeAdapter<?> getJavaTypeAdapter() {
    return getXmlObject().isSetAsType() ? getXmlObject().getAsType() : MetaschemaDataTypeProvider.DEFAULT_DATA_TYPE;
  }

  @Override
  public boolean hasJsonValueKeyFlagInstance() {
    return getXmlObject().isSetJsonValueKeyFlag() && getXmlObject().getJsonValueKeyFlag().isSetFlagRef();
  }

  @Override
  public IFlagInstance getJsonValueKeyFlagInstance() {
    IFlagInstance retval = null;
    if (getXmlObject().isSetJsonValueKeyFlag() && getXmlObject().getJsonValueKeyFlag().isSetFlagRef()) {
      String namespace = getQName().getNamespace();
      String name = ObjectUtils.notNull(getXmlObject().getJsonValueKeyFlag().getFlagRef());

      retval = getFlagInstanceByName(IEnhancedQName.of(namespace, name).getIndexPosition());
    }
    return retval;
  }

  @Override
  public String getJsonValueKeyName() {
    return getXmlObject().getJsonValueKey();
  }

  @SuppressWarnings("null")
  @Override
  public ModuleScope getModuleScope() {
    return getXmlObject().isSetScope() ? getXmlObject().getScope() : DEFAULT_MODULE_SCOPE;
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
