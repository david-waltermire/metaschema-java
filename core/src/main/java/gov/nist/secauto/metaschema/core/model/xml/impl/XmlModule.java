/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.xml.impl;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.model.AbstractModule;
import gov.nist.secauto.metaschema.core.model.IAssemblyDefinition;
import gov.nist.secauto.metaschema.core.model.IFieldDefinition;
import gov.nist.secauto.metaschema.core.model.IFlagDefinition;
import gov.nist.secauto.metaschema.core.model.IModelDefinition;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.MetaschemaException;
import gov.nist.secauto.metaschema.core.model.ModelInitializationException;
import gov.nist.secauto.metaschema.core.model.xml.IXmlMetaschemaModule;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.GlobalAssemblyDefinitionType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.GlobalFieldDefinitionType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.GlobalFlagDefinitionType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.METASCHEMADocument;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.METASCHEMADocument.METASCHEMA;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.NamespaceBindingType;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.CustomCollectors;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.xmlbeans.XmlCursor;

import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * Represents a Metaschema module based on XMLBeans-based data.
 */
@SuppressWarnings("PMD.CouplingBetweenObjects")
public class XmlModule
    extends AbstractModule<
        IXmlMetaschemaModule,
        IModelDefinition,
        IFlagDefinition,
        IFieldDefinition,
        IAssemblyDefinition>
    implements IXmlMetaschemaModule {
  private static final Logger LOGGER = LogManager.getLogger(XmlModule.class);

  @NonNull
  private static final String METASCHEMA_NS_DECLARATION_XPATH
      = "declare namespace m='http://csrc.nist.gov/ns/oscal/metaschema/1.0';";
  @NonNull
  private static final String FLAG_DEFINITION_XPATH
      = METASCHEMA_NS_DECLARATION_XPATH + "$this/m:define-flag";
  @NonNull
  private static final String FIELD_DEFINITION_XPATH
      = METASCHEMA_NS_DECLARATION_XPATH + "$this/m:define-field";
  @NonNull
  private static final String ASSEMBLY_DEFINITION_XPATH
      = METASCHEMA_NS_DECLARATION_XPATH + "$this/m:define-assembly";

  @NonNull
  private final Lazy<StaticContext> staticContext;
  @NonNull
  private final METASCHEMADocument module;
  private final Lazy<Definitions> definitions;
  @NonNull
  private final ISource source;

  /**
   * Constructs a new Metaschema instance.
   *
   * @param resource
   *          the resource from which the module was loaded
   * @param xmlObject
   *          the XML source of the module definition bound to Java objects
   * @param importedModules
   *          the modules imported by this module
   * @throws MetaschemaException
   *           if a processing error occurs
   */
  public XmlModule(
      @NonNull URI resource,
      @NonNull METASCHEMADocument xmlObject,
      @NonNull List<? extends IXmlMetaschemaModule> importedModules) throws MetaschemaException {
    super(importedModules);

    METASCHEMADocument.METASCHEMA moduleXml = ObjectUtils.requireNonNull(xmlObject.getMETASCHEMA());

    this.staticContext = ObjectUtils.notNull(Lazy.of(() -> {
      StaticContext.Builder builder = StaticContext.builder()
          .baseUri(resource)
          .defaultModelNamespace(ObjectUtils.requireNonNull(moduleXml.getNamespace()));

      getNamespaceBindings()
          .forEach((prefix, ns) -> builder.namespace(
              ObjectUtils.notNull(prefix), ObjectUtils.notNull(ns)));

      return builder.build();
    }));
    this.module = xmlObject;
    this.definitions = Lazy.of(() -> new Definitions(moduleXml));
    this.source = ISource.moduleSource(this);
  }

  @Override
  public StaticContext getModuleStaticContext() {
    return ObjectUtils.notNull(staticContext.get());
  }

  @Override
  public ISource getSource() {
    return source;
  }

  @NonNull
  @Override
  public URI getLocation() {
    return ObjectUtils.notNull(getModuleStaticContext().getBaseUri());
  }

  @Override
  public String getLocationHint() {
    return ObjectUtils.notNull(getLocation().toASCIIString());
  }

  /**
   * Get the XMLBeans representation of the Metaschema module.
   *
   * @return the XMLBean for the Metaschema module
   */
  @NonNull
  protected METASCHEMADocument.METASCHEMA getXmlModule() {
    return ObjectUtils.notNull(module.getMETASCHEMA());
  }

  @SuppressWarnings("null")
  @Override
  public MarkupLine getName() {
    return MarkupStringConverter.toMarkupString(getXmlModule().getSchemaName());
  }

  @SuppressWarnings("null")
  @Override
  public String getVersion() {
    return getXmlModule().getSchemaVersion();
  }

  @SuppressWarnings("null")
  @Override
  public MarkupMultiline getRemarks() {
    return getXmlModule().isSetRemarks() ? MarkupStringConverter.toMarkupString(getXmlModule().getRemarks())
        : null;
  }

  @SuppressWarnings("null")
  @Override
  public String getShortName() {
    return getXmlModule().getShortName();
  }

  @SuppressWarnings("null")
  @Override
  public URI getXmlNamespace() {
    return URI.create(getXmlModule().getNamespace());
  }

  @SuppressWarnings("null")
  @Override
  public URI getJsonBaseUri() {
    return URI.create(getXmlModule().getJsonBaseUri());
  }

  @Override
  public Map<String, String> getNamespaceBindings() {
    return ObjectUtils.notNull(getXmlModule().getNamespaceBindingList().stream()
        .collect(Collectors.toMap(
            NamespaceBindingType::getPrefix,
            NamespaceBindingType::getUri,
            (v1, v2) -> v2,
            LinkedHashMap::new)));
  }

  @NonNull
  private Definitions getDefinitions() {
    return ObjectUtils.notNull(definitions.get());
  }

  @SuppressWarnings("null")
  @Override
  public Collection<IAssemblyDefinition> getAssemblyDefinitions() {
    return getDefinitions().getAssemblyDefinitionMap().values();
  }

  @Override
  public IAssemblyDefinition getAssemblyDefinitionByName(@NonNull Integer name) {
    return getDefinitions().getAssemblyDefinitionMap().get(name);
  }

  @SuppressWarnings("null")
  @Override
  public Collection<IFieldDefinition> getFieldDefinitions() {
    return getDefinitions().getFieldDefinitionMap().values();
  }

  @Override
  public IFieldDefinition getFieldDefinitionByName(@NonNull Integer name) {
    return getDefinitions().getFieldDefinitionMap().get(name);
  }

  @SuppressWarnings("null")
  @Override
  public List<IModelDefinition> getAssemblyAndFieldDefinitions() {
    return Stream.concat(getAssemblyDefinitions().stream(), getFieldDefinitions().stream())
        .collect(Collectors.toList());
  }

  @SuppressWarnings("null")
  @Override
  public Collection<IFlagDefinition> getFlagDefinitions() {
    return getDefinitions().getFlagDefinitionMap().values();
  }

  @Override
  public IFlagDefinition getFlagDefinitionByName(@NonNull IEnhancedQName name) {
    return getDefinitions().getFlagDefinitionMap().get(name);
  }

  @SuppressWarnings("null")
  @Override
  public Collection<? extends IAssemblyDefinition> getRootAssemblyDefinitions() {
    return getDefinitions().getRootAssemblyDefinitionMap().values();
  }

  private final class Definitions {
    private final Map<IEnhancedQName, IFlagDefinition> flagDefinitions;
    private final Map<Integer, IFieldDefinition> fieldDefinitions;
    private final Map<Integer, IAssemblyDefinition> assemblyDefinitions;
    private final Map<Integer, IAssemblyDefinition> rootAssemblyDefinitions;

    private Definitions(@NonNull METASCHEMA metaschemaNode) {

      // handle definitions in this module
      // TODO: switch implementation to use the XmlObjectParser
      try (XmlCursor cursor = metaschemaNode.newCursor()) {
        assert cursor != null;

        this.flagDefinitions = parseFlags(cursor);
        this.fieldDefinitions = parseFields(cursor);
        this.assemblyDefinitions = parseAssemblies(cursor);
        this.rootAssemblyDefinitions = this.assemblyDefinitions.isEmpty()
            ? Collections.emptyMap()
            : Collections.unmodifiableMap(this.assemblyDefinitions.values().stream()
                .filter(IAssemblyDefinition::isRoot)
                .collect(CustomCollectors.toMap(
                    def -> def.getRootQName().getIndexPosition(),
                    CustomCollectors.identity(),
                    (key, v1, v2) -> {
                      throw new ModelInitializationException(
                          String.format("Duplicate root QName '%s' for root assemblies: %s and %s in %s.",
                              IEnhancedQName.of(key).or(null),
                              v1.getName(),
                              v2.getName(),
                              XmlObjectParser.toLocation(cursor)));
                    },
                    LinkedHashMap::new)));
      }
    }

    @SuppressWarnings({
        "PMD.UseConcurrentHashMap",
        "PMD.AvoidInstantiatingObjectsInLoops"
    })
    @NonNull
    private Map<IEnhancedQName, IFlagDefinition> parseFlags(@NonNull XmlCursor cursor) {
      cursor.push();

      // start with flag definitions
      cursor.selectPath(FLAG_DEFINITION_XPATH);

      Map<IEnhancedQName, IFlagDefinition> flags = new LinkedHashMap<>();
      while (cursor.toNextSelection()) {
        GlobalFlagDefinitionType obj = ObjectUtils.notNull((GlobalFlagDefinitionType) cursor.getObject());
        XmlGlobalFlagDefinition flag = new XmlGlobalFlagDefinition(obj, XmlModule.this);
        if (LOGGER.isTraceEnabled()) {
          LOGGER.trace("New flag definition '{}'", flag.toCoordinates());
        }
        flags.put(flag.getDefinitionQName(), flag);
      }

      cursor.pop();

      return flags.isEmpty()
          ? CollectionUtil.emptyMap()
          : CollectionUtil.unmodifiableMap(flags);
    }

    @SuppressWarnings({
        "PMD.UseConcurrentHashMap",
        "PMD.AvoidInstantiatingObjectsInLoops"
    })
    @NonNull
    private Map<Integer, IFieldDefinition> parseFields(@NonNull XmlCursor cursor) {
      cursor.push();

      // now field definitions
      cursor.selectPath(FIELD_DEFINITION_XPATH);

      Map<Integer, IFieldDefinition> fields = new LinkedHashMap<>();
      while (cursor.toNextSelection()) {
        GlobalFieldDefinitionType obj = ObjectUtils.notNull((GlobalFieldDefinitionType) cursor.getObject());
        XmlGlobalFieldDefinition field = new XmlGlobalFieldDefinition(obj, XmlModule.this);
        if (LOGGER.isTraceEnabled()) {
          LOGGER.trace("New field definition '{}'", field.toCoordinates());
        }
        fields.put(field.getDefinitionQName().getIndexPosition(), field);
      }

      cursor.pop();

      return fields.isEmpty()
          ? CollectionUtil.emptyMap()
          : CollectionUtil.unmodifiableMap(fields);
    }

    @SuppressWarnings({
        "PMD.UseConcurrentHashMap",
        "PMD.AvoidInstantiatingObjectsInLoops"
    })
    @NonNull
    private Map<Integer, IAssemblyDefinition> parseAssemblies(XmlCursor cursor) {
      cursor.push();

      // finally assembly definitions
      cursor.selectPath(ASSEMBLY_DEFINITION_XPATH);

      Map<Integer, IAssemblyDefinition> assemblies = new LinkedHashMap<>();
      while (cursor.toNextSelection()) {
        GlobalAssemblyDefinitionType obj = ObjectUtils.notNull((GlobalAssemblyDefinitionType) cursor.getObject());
        XmlGlobalAssemblyDefinition assembly = new XmlGlobalAssemblyDefinition(obj, XmlModule.this);
        if (LOGGER.isTraceEnabled()) {
          LOGGER.trace("New assembly definition '{}'", assembly.toCoordinates());
        }
        assemblies.put(assembly.getDefinitionQName().getIndexPosition(), assembly);
      }

      cursor.pop();

      return assemblies.isEmpty()
          ? CollectionUtil.emptyMap()
          : CollectionUtil.unmodifiableMap(assemblies);
    }

    public Map<IEnhancedQName, IFlagDefinition> getFlagDefinitionMap() {
      return flagDefinitions;
    }

    public Map<Integer, IFieldDefinition> getFieldDefinitionMap() {
      return fieldDefinitions;
    }

    public Map<Integer, IAssemblyDefinition> getAssemblyDefinitionMap() {
      return assemblyDefinitions;
    }

    public Map<Integer, ? extends IAssemblyDefinition> getRootAssemblyDefinitionMap() {
      return rootAssemblyDefinitions;
    }

  }
}
