/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.xml.impl;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.model.AbstractChoiceInstance;
import gov.nist.secauto.metaschema.core.model.DefaultChoiceModelBuilder;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IChoiceInstance;
import gov.nist.secauto.metaschema.core.model.IContainerModelSupport;
import gov.nist.secauto.metaschema.core.model.IFieldInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.xml.XmlModuleConstants;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.AssemblyReferenceType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.ChoiceType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.FieldReferenceType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.InlineAssemblyDefinitionType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.InlineFieldDefinitionType;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlObject;

import java.util.Map;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

class XmlChoiceInstance
    extends AbstractChoiceInstance<
        IAssemblyDefinition,
        IModelInstanceAbsolute,
        INamedModelInstanceAbsolute,
        IFieldInstanceAbsolute,
        IAssemblyInstanceAbsolute> {
  @NonNull
  private final ChoiceType xmlChoice;
  @NonNull
  private final Lazy<IContainerModelSupport<
      IModelInstanceAbsolute,
      INamedModelInstanceAbsolute,
      IFieldInstanceAbsolute,
      IAssemblyInstanceAbsolute>> modelContainer;

  @NonNull
  private static final XmlObjectParser<Pair<IChoiceInstance, ModelBuilder>> XML_MODEL_PARSER
      = new XmlObjectParser<>(ObjectUtils.notNull(
          Map.ofEntries(
              Map.entry(XmlModuleConstants.ASSEMBLY_QNAME, XmlChoiceInstance::handleAssembly),
              Map.entry(XmlModuleConstants.DEFINE_ASSEMBLY_QNAME, XmlChoiceInstance::handleDefineAssembly),
              Map.entry(XmlModuleConstants.FIELD_QNAME, XmlChoiceInstance::handleField),
              Map.entry(XmlModuleConstants.DEFINE_FIELD_QNAME, XmlChoiceInstance::handleDefineField)))) {

        @SuppressWarnings("synthetic-access")
        @Override
        protected Handler<Pair<IChoiceInstance, ModelBuilder>> identifyHandler(
            XmlCursor cursor,
            XmlObject obj) {
          Handler<Pair<IChoiceInstance, ModelBuilder>> retval;
          if (obj instanceof FieldReferenceType) {
            retval = XmlChoiceInstance::handleField;
          } else if (obj instanceof InlineFieldDefinitionType) {
            retval = XmlChoiceInstance::handleDefineField;
          } else if (obj instanceof AssemblyReferenceType) {
            retval = XmlChoiceInstance::handleAssembly;
          } else if (obj instanceof InlineAssemblyDefinitionType) {
            retval = XmlChoiceInstance::handleDefineAssembly;
          } else {
            retval = super.identifyHandler(cursor, obj);
          }
          return retval;
        }
      };

  /**
   * Parse a choice group XMLBeans object.
   *
   * @param xmlObject
   *          the XMLBeans object
   * @param parent
   *          the parent Metaschema node, either an assembly definition or choice
   */
  private static IContainerModelSupport<
      IModelInstanceAbsolute,
      INamedModelInstanceAbsolute,
      IFieldInstanceAbsolute,
      IAssemblyInstanceAbsolute> newContainer(
          @NonNull ChoiceType xmlObject,
          @NonNull IChoiceInstance parent) {
    ModelBuilder builder = new ModelBuilder();
    XML_MODEL_PARSER.parse(
        parent.getContainingModule().getSource(),
        xmlObject,
        Pair.of(parent, builder));
    return builder.buildChoice();
  }

  private static final class ModelBuilder
      extends DefaultChoiceModelBuilder<
          IModelInstanceAbsolute,
          INamedModelInstanceAbsolute,
          IFieldInstanceAbsolute,
          IAssemblyInstanceAbsolute> {
    // no other methods
  }

  @SuppressWarnings("unused")
  private static void handleField(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IChoiceInstance, ModelBuilder> state) {
    IFieldInstanceAbsolute instance = new XmlFieldInstance(
        (FieldReferenceType) obj,
        ObjectUtils.notNull(state.getLeft()));
    ObjectUtils.notNull(state.getRight()).append(instance);
  }

  @SuppressWarnings("unused")
  private static void handleDefineField(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IChoiceInstance, ModelBuilder> state) {
    IFieldInstanceAbsolute instance = new XmlInlineFieldDefinition(
        (InlineFieldDefinitionType) obj,
        ObjectUtils.notNull(state.getLeft()));
    ObjectUtils.notNull(state.getRight()).append(instance);
  }

  @SuppressWarnings("unused")
  private static void handleAssembly(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IChoiceInstance, ModelBuilder> state) {
    IAssemblyInstanceAbsolute instance = new XmlAssemblyInstance(
        (AssemblyReferenceType) obj,
        ObjectUtils.notNull(state.getLeft()));
    ObjectUtils.notNull(state.getRight()).append(instance);
  }

  @SuppressWarnings("unused")
  private static void handleDefineAssembly(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IChoiceInstance, ModelBuilder> state) {
    IAssemblyInstanceAbsolute instance = new XmlInlineAssemblyDefinition(
        (InlineAssemblyDefinitionType) obj,
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
  public XmlChoiceInstance(
      @NonNull ChoiceType xmlObject,
      @NonNull IAssemblyDefinition parent) {
    super(parent);
    this.xmlChoice = xmlObject;
    this.modelContainer = ObjectUtils.notNull(Lazy.of(() -> newContainer(xmlObject, this)));
  }

  @Override
  public IContainerModelSupport<
      IModelInstanceAbsolute,
      INamedModelInstanceAbsolute,
      IFieldInstanceAbsolute,
      IAssemblyInstanceAbsolute> getModelContainer() {
    return ObjectUtils.notNull(modelContainer.get());
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
  protected ChoiceType getXmlObject() {
    return xmlChoice;
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
