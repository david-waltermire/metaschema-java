/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.xml.impl;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.model.AbstractChoiceGroupInstance;
import gov.nist.secauto.metaschema.core.model.DefaultChoiceGroupModelBuilder;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstanceGrouped;
import gov.nist.secauto.metaschema.core.model.IChoiceGroupInstance;
import gov.nist.secauto.metaschema.core.model.IContainerModelSupport;
import gov.nist.secauto.metaschema.core.model.IFieldInstanceGrouped;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceGrouped;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.JsonGroupAsBehavior;
import gov.nist.secauto.metaschema.core.model.XmlGroupAsBehavior;
import gov.nist.secauto.metaschema.core.model.xml.XmlModuleConstants;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.GroupedAssemblyReferenceType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.GroupedChoiceType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.GroupedFieldReferenceType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.GroupedInlineAssemblyDefinitionType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.GroupedInlineFieldDefinitionType;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlObject;

import java.util.Map;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

class XmlChoiceGroupInstance
    extends AbstractChoiceGroupInstance<
        IAssemblyDefinition,
        INamedModelInstanceGrouped,
        IFieldInstanceGrouped,
        IAssemblyInstanceGrouped> {
  @NonNull
  private final GroupedChoiceType xmlObject;
  @NonNull
  private final Lazy<IContainerModelSupport<
      INamedModelInstanceGrouped,
      INamedModelInstanceGrouped,
      IFieldInstanceGrouped,
      IAssemblyInstanceGrouped>> modelContainer;

  @NonNull
  private static final XmlObjectParser<Pair<IChoiceGroupInstance, ModelBuilder>> XML_MODEL_PARSER
      = new XmlObjectParser<>(ObjectUtils.notNull(
          Map.ofEntries(
              Map.entry(XmlModuleConstants.ASSEMBLY_QNAME, XmlChoiceGroupInstance::handleAssembly),
              Map.entry(XmlModuleConstants.DEFINE_ASSEMBLY_QNAME, XmlChoiceGroupInstance::handleDefineAssembly),
              Map.entry(XmlModuleConstants.FIELD_QNAME, XmlChoiceGroupInstance::handleField),
              Map.entry(XmlModuleConstants.DEFINE_FIELD_QNAME, XmlChoiceGroupInstance::handleDefineField)))) {

        @SuppressWarnings("synthetic-access")
        @Override
        protected Handler<Pair<IChoiceGroupInstance, ModelBuilder>>
            identifyHandler(XmlCursor cursor, XmlObject obj) {
          Handler<Pair<IChoiceGroupInstance, ModelBuilder>> retval;
          if (obj instanceof GroupedFieldReferenceType) {
            retval = XmlChoiceGroupInstance::handleField;
          } else if (obj instanceof GroupedInlineFieldDefinitionType) {
            retval = XmlChoiceGroupInstance::handleDefineField;
          } else if (obj instanceof GroupedAssemblyReferenceType) {
            retval = XmlChoiceGroupInstance::handleAssembly;
          } else if (obj instanceof GroupedInlineAssemblyDefinitionType) {
            retval = XmlChoiceGroupInstance::handleDefineAssembly;
          } else {
            retval = super.identifyHandler(cursor, obj);
          }
          return retval;
        }
      };

  /**
   * Parse a choice group XMLBeans object.
   *
   * @param source
   *          information about the parsed resource
   * @param xmlObject
   *          the XMLBeans object
   * @param parent
   *          the parent Metaschema node, either an assembly definition or choice
   */
  private static IContainerModelSupport<
      INamedModelInstanceGrouped,
      INamedModelInstanceGrouped,
      IFieldInstanceGrouped,
      IAssemblyInstanceGrouped> newContainer(
          @NonNull ISource source,
          @NonNull GroupedChoiceType xmlObject,
          @NonNull IChoiceGroupInstance parent) {
    ModelBuilder builder = new ModelBuilder();
    XML_MODEL_PARSER.parse(source, xmlObject, Pair.of(parent, builder));
    return builder.buildChoiceGroup();
  }

  private static final class ModelBuilder
      extends DefaultChoiceGroupModelBuilder<
          INamedModelInstanceGrouped,
          IFieldInstanceGrouped,
          IAssemblyInstanceGrouped> {
    // no other methods
  }

  @SuppressWarnings("unused")
  private static void handleField(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IChoiceGroupInstance, ModelBuilder> state) {
    IFieldInstanceGrouped instance = new XmlGroupedFieldInstance(
        (GroupedFieldReferenceType) obj,
        ObjectUtils.notNull(state.getLeft()));
    ObjectUtils.notNull(state.getRight()).append(instance);
  }

  @SuppressWarnings("unused")
  private static void handleDefineField(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IChoiceGroupInstance, ModelBuilder> state) {
    IFieldInstanceGrouped instance = new XmlGroupedInlineFieldDefinition(
        (GroupedInlineFieldDefinitionType) obj,
        ObjectUtils.notNull(state.getLeft()));
    ObjectUtils.notNull(state.getRight()).append(instance);
  }

  @SuppressWarnings("unused")
  private static void handleAssembly(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IChoiceGroupInstance, ModelBuilder> state) {
    IAssemblyInstanceGrouped instance = new XmlGroupedAssemblyInstance(
        (GroupedAssemblyReferenceType) obj,
        ObjectUtils.notNull(state.getLeft()));
    ObjectUtils.notNull(state.getRight()).append(instance);
  }

  @SuppressWarnings("unused")
  private static void handleDefineAssembly(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IChoiceGroupInstance, ModelBuilder> state) {
    IAssemblyInstanceGrouped instance = new XmlGroupedInlineAssemblyDefinition(
        (GroupedInlineAssemblyDefinitionType) obj,
        ObjectUtils.notNull(state.getLeft()));
    ObjectUtils.notNull(state.getRight()).append(instance);
  }

  /**
   * Constructs a mutually exclusive choice between two possible objects.
   *
   * @param xmlObject
   *          the XML for the choice definition bound to Java objects
   * @param parent
   *          the parent container, either a choice or assembly
   */
  public XmlChoiceGroupInstance(
      @NonNull GroupedChoiceType xmlObject,
      @NonNull IAssemblyDefinition parent) {
    super(parent);
    this.xmlObject = xmlObject;
    this.modelContainer = ObjectUtils.notNull(Lazy.of(() -> newContainer(
        parent.getContainingModule().getSource(),
        xmlObject,
        this)));
  }

  @Override
  public IContainerModelSupport<
      INamedModelInstanceGrouped,
      INamedModelInstanceGrouped,
      IFieldInstanceGrouped,
      IAssemblyInstanceGrouped> getModelContainer() {
    return ObjectUtils.notNull(modelContainer.get());
  }

  @Override
  public IAssemblyDefinition getOwningDefinition() {
    return getParentContainer();
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
  protected GroupedChoiceType getXmlObject() {
    return xmlObject;
  }

  @Override
  public String getJsonDiscriminatorProperty() {
    return getXmlObject().isSetDiscriminator()
        ? ObjectUtils.requireNonNull(getXmlObject().getDiscriminator())
        : DEFAULT_JSON_DISCRIMINATOR_PROPERTY_NAME;
  }

  @Override
  public String getJsonKeyFlagInstanceName() {
    return getXmlObject().isSetJsonKey() ? getXmlObject().getJsonKey().getFlagRef() : null;
  }

  @Override
  public String getGroupAsName() {
    return getXmlObject().getGroupAs().getName();
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

  @Override
  public MarkupMultiline getRemarks() {
    // remarks not supported
    return null;
  }

  // -------------------------------------
  // - End XmlBeans driven code - CPD-ON -
  // -------------------------------------
}
