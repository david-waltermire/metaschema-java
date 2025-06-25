/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.io.xml;

import gov.nist.secauto.metaschema.core.model.IBoundObject;
import gov.nist.secauto.metaschema.databind.io.IProblemHandler;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelAssembly;
import gov.nist.secauto.metaschema.databind.model.IBoundDefinitionModelComplex;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceFlag;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModel;

import java.io.IOException;
import java.util.Collection;

import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;

import edu.umd.cs.findbugs.annotations.NonNull;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface IXmlProblemHandler extends IProblemHandler {
  /**
   * Callback used to handle an attribute that is unknown to the model being
   * parsed.
   *
   * @param parentDefinition
   *          the bound class currently describing the data being parsed
   * @param targetObject
   *          the Java object for the {@code parentDefinition}
   * @param attribute
   *          the unknown attribute
   * @param parsingContext
   *          the XML parsing context used for parsing
   * @return {@code true} if the attribute was handled by this method, or
   *         {@code false} otherwise
   * @throws IOException
   *           if an error occurred while handling the unrecognized data
   */
  default boolean handleUnknownAttribute(
      @NonNull IBoundDefinitionModelComplex parentDefinition,
      @NonNull IBoundObject targetObject,
      @NonNull Attribute attribute,
      @NonNull IXmlParsingContext parsingContext) throws IOException {
    return false;
  }

  /**
   * Callback used to handle an element that is unknown to the model being parsed.
   *
   * @param parentDefinition
   *          the bound assembly class on which the missing instances are found
   * @param targetObject
   *          the Java object for the {@code parentDefinition}
   * @param start
   *          the parsed XML start element
   * @param parsingContext
   *          the XML parsing context used for parsing
   * @return {@code true} if the element was handled by this method, or
   *         {@code false} otherwise
   * @throws IOException
   *           if an error occurred while handling the unrecognized data
   */
  default boolean handleUnknownElement(
      @NonNull IBoundDefinitionModelAssembly parentDefinition,
      @NonNull IBoundObject targetObject,
      @NonNull StartElement start,
      @NonNull IXmlParsingContext parsingContext) throws IOException {
    return false;
  }

  /**
   * A callback used to handle bound flag instances for which no data was found
   * when the content was parsed.
   * <p>
   * This can be used to supply default or prescribed values based on application
   * logic.
   *
   * @param parentDefinition
   *          the bound assembly class on which the missing instances are found
   * @param targetObject
   *          the Java object for the {@code parentDefinition}
   * @param unhandledInstances
   *          the set of instances that had no data to parse
   * @throws IOException
   *           if an error occurred while handling the missing instances
   */
  default void handleMissingFlagInstances(
      @NonNull IBoundDefinitionModelComplex parentDefinition,
      @NonNull IBoundObject targetObject,
      @NonNull Collection<IBoundInstanceFlag> unhandledInstances)
      throws IOException {
    handleMissingInstances(parentDefinition, targetObject, unhandledInstances);
  }

  /**
   * A callback used to handle bound model instances for which no data was found
   * when the content was parsed.
   * <p>
   * This can be used to supply default or prescribed values based on application
   * logic.
   *
   * @param parentDefinition
   *          the bound assembly class on which the missing instances are found
   * @param targetObject
   *          the Java object for the {@code parentDefinition}
   * @param unhandledInstances
   *          the set of instances that had no data to parse
   * @throws IOException
   *           if an error occurred while handling the missing instances
   */
  default void handleMissingModelInstances(
      @NonNull IBoundDefinitionModelAssembly parentDefinition,
      @NonNull IBoundObject targetObject,
      @NonNull Collection<? extends IBoundInstanceModel<?>> unhandledInstances)
      throws IOException {
    handleMissingInstances(parentDefinition, targetObject, unhandledInstances);
  }
}
