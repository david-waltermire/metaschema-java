/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.xml.impl;

import gov.nist.secauto.metaschema.core.model.IResourceLocation;

import org.apache.xmlbeans.XmlObject;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface IXmlObjectBinding {
  /**
   * Get the underlying XML data.
   *
   * @return the underlying XML data
   */
  @NonNull
  XmlObject getXmlObject();

  /**
   * Get the location information for this object, if the location is available.
   *
   * @return the location information or {@code null} if the location information
   *         is unavailable
   */
  @Nullable
  default IResourceLocation getLocation() {
    return XmlBeansLocation.toLocation(getXmlObject());
  }
}
