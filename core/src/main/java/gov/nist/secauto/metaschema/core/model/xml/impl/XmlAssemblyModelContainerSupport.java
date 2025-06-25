/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.xml.impl;

import gov.nist.secauto.metaschema.core.model.DefaultAssemblyModelBuilder;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IAssemblyInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IChoiceGroupInstance;
import gov.nist.secauto.metaschema.core.model.IChoiceInstance;
import gov.nist.secauto.metaschema.core.model.IContainerModelAssemblySupport;
import gov.nist.secauto.metaschema.core.model.IFieldInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.IModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.INamedModelInstanceAbsolute;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.ModelInitializationException;
import gov.nist.secauto.metaschema.core.model.xml.XmlModuleConstants;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.AssemblyModelType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.AssemblyReferenceType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.ChoiceType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.FieldReferenceType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.GroupedChoiceType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.InlineAssemblyDefinitionType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.InlineFieldDefinitionType;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlObject;

import java.util.Map;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Used to construct the model of an assembly definition based on XMLBeans-based
 * data.
 */
public final class XmlAssemblyModelContainerSupport {
  @NonNull
  private static final XmlObjectParser<Pair<IAssemblyDefinition, ModelBuilder>> XML_MODEL_PARSER
      = new XmlObjectParser<>(ObjectUtils.notNull(
          Map.ofEntries(
              Map.entry(XmlModuleConstants.ASSEMBLY_QNAME, XmlAssemblyModelContainerSupport::handleAssemmbly),
              Map.entry(XmlModuleConstants.DEFINE_ASSEMBLY_QNAME,
                  XmlAssemblyModelContainerSupport::handleDefineAssembly),
              Map.entry(XmlModuleConstants.FIELD_QNAME, XmlAssemblyModelContainerSupport::handleField),
              Map.entry(XmlModuleConstants.DEFINE_FIELD_QNAME, XmlAssemblyModelContainerSupport::handleDefineField),
              Map.entry(XmlModuleConstants.CHOICE_QNAME, XmlAssemblyModelContainerSupport::handleChoice),
              Map.entry(XmlModuleConstants.CHOICE_GROUP_QNAME, XmlAssemblyModelContainerSupport::handleChoiceGroup)))) {

        @SuppressWarnings("synthetic-access")
        @Override
        protected Handler<Pair<IAssemblyDefinition, ModelBuilder>>
            identifyHandler(XmlCursor cursor, XmlObject obj) {
          Handler<Pair<IAssemblyDefinition, ModelBuilder>> retval;
          if (obj instanceof FieldReferenceType) {
            retval = XmlAssemblyModelContainerSupport::handleField;
          } else if (obj instanceof InlineFieldDefinitionType) {
            retval = XmlAssemblyModelContainerSupport::handleDefineField;
          } else if (obj instanceof AssemblyReferenceType) {
            retval = XmlAssemblyModelContainerSupport::handleAssemmbly;
          } else if (obj instanceof InlineAssemblyDefinitionType) {
            retval = XmlAssemblyModelContainerSupport::handleDefineAssembly;
          } else if (obj instanceof ChoiceType) {
            retval = XmlAssemblyModelContainerSupport::handleChoice;
          } else if (obj instanceof GroupedChoiceType) {
            retval = XmlAssemblyModelContainerSupport::handleChoiceGroup;
          } else {
            retval = super.identifyHandler(cursor, obj);
          }
          return retval;
        }
      };

  /**
   * Parse an assembly XMLBeans object.
   *
   * @param xmlObject
   *          the XMLBeans assembly model object, which may be {@code null}
   * @param parent
   *          the parent assembly definition, either an assembly definition or
   *          choice
   * @return the model container
   */
  @SuppressWarnings("PMD.ShortMethodName")
  public static IContainerModelAssemblySupport<
      IModelInstanceAbsolute,
      INamedModelInstanceAbsolute,
      IFieldInstanceAbsolute,
      IAssemblyInstanceAbsolute,
      IChoiceInstance,
      IChoiceGroupInstance> of(
          @Nullable AssemblyModelType xmlObject,
          @NonNull IAssemblyDefinition parent) {
    return xmlObject == null
        ? IContainerModelAssemblySupport.empty()
        : newContainer(
            parent.getContainingModule().getSource(),
            xmlObject,
            parent);
  }

  private static IContainerModelAssemblySupport<
      IModelInstanceAbsolute,
      INamedModelInstanceAbsolute,
      IFieldInstanceAbsolute,
      IAssemblyInstanceAbsolute,
      IChoiceInstance,
      IChoiceGroupInstance> newContainer(
          @NonNull ISource source,
          @NonNull AssemblyModelType xmlObject,
          @NonNull IAssemblyDefinition parent) {
    ModelBuilder builder = new ModelBuilder();
    XML_MODEL_PARSER.parse(source, xmlObject, Pair.of(parent, builder));
    return builder.buildAssembly();
  }

  @SuppressWarnings("unused")
  private static void handleField(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IAssemblyDefinition, ModelBuilder> state) {
    IFieldInstanceAbsolute instance = new XmlFieldInstance(
        (FieldReferenceType) obj,
        ObjectUtils.notNull(state.getLeft()));
    ObjectUtils.notNull(state.getRight()).append(instance);
  }

  @SuppressWarnings("unused")
  private static void handleDefineField(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IAssemblyDefinition, ModelBuilder> state) {
    IFieldInstanceAbsolute instance = new XmlInlineFieldDefinition(
        (InlineFieldDefinitionType) obj,
        ObjectUtils.notNull(state.getLeft()));
    ObjectUtils.notNull(state.getRight()).append(instance);
  }

  @SuppressWarnings("unused")
  private static void handleAssemmbly(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IAssemblyDefinition, ModelBuilder> state) {
    IAssemblyInstanceAbsolute instance = new XmlAssemblyInstance(
        (AssemblyReferenceType) obj,
        ObjectUtils.notNull(state.getLeft()));
    ObjectUtils.notNull(state.getRight()).append(instance);
  }

  @SuppressWarnings("unused")
  private static void handleDefineAssembly(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IAssemblyDefinition, ModelBuilder> state) {
    IAssemblyInstanceAbsolute instance = new XmlInlineAssemblyDefinition(
        (InlineAssemblyDefinitionType) obj,
        ObjectUtils.notNull(state.getLeft()));
    ObjectUtils.notNull(state.getRight()).append(instance);
  }

  @SuppressWarnings("unused")
  private static void handleChoice(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IAssemblyDefinition, ModelBuilder> state) {
    XmlChoiceInstance instance = new XmlChoiceInstance(
        (ChoiceType) obj,
        ObjectUtils.notNull(state.getLeft()));
    ObjectUtils.notNull(state.getRight()).append(instance);
  }

  @SuppressWarnings("unused")
  private static void handleChoiceGroup(
      @NonNull ISource source,
      @NonNull XmlObject obj,
      Pair<IAssemblyDefinition, ModelBuilder> state) {
    XmlChoiceGroupInstance instance = new XmlChoiceGroupInstance(
        (GroupedChoiceType) obj,
        ObjectUtils.notNull(state.getLeft()));

    String groupAsName = instance.getGroupAsName();
    if (groupAsName == null) {
      String location = XmlObjectParser.toLocation(obj);
      location = location.isEmpty() ? "" : " at location " + location;
      throw new ModelInitializationException(
          String.format("Missing group-as for a choice group within the definition '%s'%s.",
              instance.getContainingDefinition().getName(),
              location));
    }
    ObjectUtils.notNull(state.getRight()).append(instance);
  }

  private static final class ModelBuilder
      extends DefaultAssemblyModelBuilder<
          IModelInstanceAbsolute,
          INamedModelInstanceAbsolute,
          IFieldInstanceAbsolute,
          IAssemblyInstanceAbsolute,
          IChoiceInstance,
          IChoiceGroupInstance> {
    // no other methods
  }

  private XmlAssemblyModelContainerSupport() {
    // disable construction
  }
}
