/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.xml.impl; // NOPMD - intentional

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.model.AbstractInlineFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.IContainerFlagSupport;
import gov.nist.secauto.metaschema.core.model.IContainerModel;
import gov.nist.secauto.metaschema.core.model.IFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IFieldInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IFlagInstance;
import gov.nist.secauto.metaschema.core.model.IModelElementVisitor;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.JsonGroupAsBehavior;
import gov.nist.secauto.metaschema.core.model.XmlGroupAsBehavior;
import gov.nist.secauto.metaschema.core.model.constraint.IValueConstrained;
import gov.nist.secauto.metaschema.core.model.constraint.ValueConstraintSet;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.InlineFieldDefinitionType;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Map;
import java.util.Set;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import nl.talsmasoftware.lazy4j.Lazy;

class XmlInlineFieldDefinition
    extends AbstractInlineFieldDefinition<
        IContainerModel,
        IFieldDefinition,
        IFieldInstanceAbsolute,
        IAssemblyDefinition,
        IFlagInstance>
    implements IFieldInstanceAbsolute {
  @NonNull
  private final InlineFieldDefinitionType xmlObject;
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
   * @param parent
   *          the parent container, either a choice or assembly
   */
  @SuppressWarnings("PMD.NullAssignment")
  public XmlInlineFieldDefinition(
      @NonNull InlineFieldDefinitionType xmlObject,
      @NonNull IContainerModel parent) {
    super(parent);
    this.xmlObject = xmlObject;
    this.defaultValue = xmlObject.isSetDefault()
        ? getJavaTypeAdapter().parse(ObjectUtils.requireNonNull(xmlObject.getDefault()))
        : null;
    this.flagContainer = ObjectUtils.notNull(Lazy.lazy(() -> XmlFlagContainerSupport.newInstance(xmlObject, this)));

    ISource source = parent.getOwningDefinition().getContainingModule().getSource();

    this.constraints = ObjectUtils.notNull(Lazy.lazy(() -> {
      IValueConstrained retval = new ValueConstraintSet(source);
      if (getXmlObject().isSetConstraint()) {
        ConstraintXmlSupport.parse(retval, ObjectUtils.notNull(getXmlObject().getConstraint()), source);
      }
      return retval;
    }));
  }

  /**
   * A visitor callback.
   *
   * @param <CONTEXT>
   *          the type of the context parameter
   * @param <RESULT>
   *          the type of the visitor result
   * @param visitor
   *          the calling visitor
   * @param context
   *          a parameter used to pass contextual information between visitors
   * @return the visitor result
   */
  @Override
  public <CONTEXT, RESULT> RESULT accept(@NonNull IModelElementVisitor<CONTEXT, RESULT> visitor, CONTEXT context) {
    return visitor.visitFieldInstance(this, context);
  }

  // ----------------------------------------
  // - Start XmlBeans driven code - CPD-OFF -
  // ----------------------------------------

  /**
   * Get the underlying XML model.
   *
   * @return the XML model
   */
  @NonNull
  protected final InlineFieldDefinitionType getXmlObject() {
    return xmlObject;
  }

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

  @Override
  public boolean isInXmlWrapped() {
    return getXmlObject().getInXml();
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
  public String getGroupAsName() {
    return getXmlObject().isSetGroupAs() ? getXmlObject().getGroupAs().getName() : null;
  }

  @Override
  public int getMinOccurs() {
    return XmlModelParser.getMinOccurs(getXmlObject().getMinOccurs());
  }

  @Override
  public int getMaxOccurs() {
    return XmlModelParser.getMaxOccurs(getXmlObject().getMaxOccurs());
  }

  @Override
  public JsonGroupAsBehavior getJsonGroupAsBehavior() {
    return XmlModelParser.getJsonGroupAsBehavior(getXmlObject().getGroupAs());
  }

  @Override
  public XmlGroupAsBehavior getXmlGroupAsBehavior() {
    return XmlModelParser.getXmlGroupAsBehavior(getXmlObject().getGroupAs());
  }

  @SuppressWarnings("null")
  @Override
  public MarkupMultiline getRemarks() {
    return getXmlObject().isSetRemarks() ? MarkupStringConverter.toMarkupString(getXmlObject().getRemarks()) : null;
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

  // @Override
  // public String getJsonKeyFlagInstanceName() {
  // return IFeatureXmlContainerFlag.super.getJsonKeyFlagInstanceName();
  // }

  // -------------------------------------
  // - End XmlBeans driven code - CPD-ON -
  // -------------------------------------
}
