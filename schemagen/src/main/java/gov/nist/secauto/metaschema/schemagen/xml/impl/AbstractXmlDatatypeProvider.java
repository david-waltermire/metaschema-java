/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.schemagen.xml.impl;

import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.codehaus.stax2.XMLStreamWriter2;
import org.eclipse.jdt.annotation.Owning;
import org.jdom2.Element;
import org.jdom2.JDOMException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.stream.XMLStreamException;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import nl.talsmasoftware.lazy4j.Lazy;

public abstract class AbstractXmlDatatypeProvider implements IDatatypeProvider {
  private Lazy<Map<String, IDatatypeContent>> datatypes;

  protected AbstractXmlDatatypeProvider() {
    this.datatypes = Lazy.of(this::initSchema);
  }

  @Owning
  @NonNull
  protected abstract InputStream getSchemaResource();

  @NonNull
  protected abstract List<Element> queryElements(JDom2XmlSchemaLoader loader);

  @NonNull
  protected abstract Map<String, IDatatypeContent> handleResults(@NonNull List<Element> items);

  private Map<String, IDatatypeContent> initSchema() {
    try (InputStream is = getSchemaResource()) {
      assert is != null;
      JDom2XmlSchemaLoader loader = new JDom2XmlSchemaLoader(is);

      List<Element> elements = queryElements(loader);

      return Collections.unmodifiableMap(handleResults(elements));
    } catch (JDOMException | IOException ex) {
      throw new IllegalStateException(ex);
    }
  }

  @Override
  @SuppressFBWarnings({ "IS2_INCONSISTENT_SYNC", "MT_CORRECTNESS", "EI_EXPOSE_REP" })
  public Map<String, IDatatypeContent> getDatatypes() {
    return ObjectUtils.notNull(datatypes.get());
  }

  @Override
  public Set<String> generateDatatypes(Set<String> requiredTypes, @NonNull XMLStreamWriter2 writer)
      throws XMLStreamException {
    Map<String, IDatatypeContent> datatypes = getDatatypes();

    Set<String> providedDatatypes = new LinkedHashSet<>();
    for (IDatatypeContent datatype : datatypes.values()) {
      String type = datatype.getTypeName();
      if (requiredTypes.contains(type)) {
        providedDatatypes.add(type);
        providedDatatypes.addAll(datatype.getDependencies());
      }
    }

    for (IDatatypeContent datatype : datatypes.values()) {
      String type = datatype.getTypeName();
      if (providedDatatypes.contains(type)) {
        datatype.write(writer);
      }
    }
    return providedDatatypes;
  }

}
