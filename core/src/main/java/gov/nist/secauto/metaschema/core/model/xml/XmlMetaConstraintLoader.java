/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.xml;

import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression;
import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.model.AbstractLoader;
import gov.nist.secauto.metaschema.core.model.IConstraintLoader;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.MetaschemaException;
import gov.nist.secauto.metaschema.core.model.constraint.AssemblyConstraintSet;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraintSet;
import gov.nist.secauto.metaschema.core.model.constraint.IModelConstrained;
import gov.nist.secauto.metaschema.core.model.constraint.MetaConstraintSet;
import gov.nist.secauto.metaschema.core.model.xml.impl.ConstraintXmlSupport;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.ImportType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.MetaschemaMetaConstraintsDocument;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.MetaschemaMetapathReferenceType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.ModelContextType;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlOptions;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Deque;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Used to load a set of external constraints from an XML-based resource.
 */
public class XmlMetaConstraintLoader
    extends AbstractLoader<List<IConstraintSet>>
    implements IConstraintLoader {

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  @Override
  protected List<IConstraintSet> parseResource(URI resource, Deque<URI> visitedResources) throws IOException {

    StaticContext.Builder builder = StaticContext.builder()
        .baseUri(resource);
    builder.useWildcardWhenNamespaceNotDefaulted(true);

    // parse this set of constraints
    MetaschemaMetaConstraintsDocument xmlObject = parseConstraintSet(resource);

    MetaschemaMetaConstraintsDocument.MetaschemaMetaConstraints constraints = xmlObject.getMetaschemaMetaConstraints();

    // now check if this constraint set imports other constraint sets
    List<ImportType> imports = constraints.getImportList();

    // handle imports
    @NonNull
    List<IConstraintSet> importedConstraints;
    if (imports.isEmpty()) {
      importedConstraints = CollectionUtil.emptyList();
    } else {
      try {
        importedConstraints = new LinkedList<>();
        for (ImportType imported : imports) {
          URI importedResource;
          try {
            importedResource = new URI(imported.getHref());
          } catch (URISyntaxException ex) {
            throw new IOException(ex);
          }
          importedResource = ObjectUtils.notNull(resource.resolve(importedResource));
          importedConstraints.addAll(loadInternal(importedResource, visitedResources));
        }
      } catch (MetaschemaException ex) {
        throw new IOException(ex);
      }
    }

    // handle namespace to prefix bindings
    constraints.getNamespaceBindingList().stream()
        .forEach(binding -> builder.namespace(
            ObjectUtils.notNull(binding.getPrefix()), ObjectUtils.notNull(binding.getUri())));
    ISource source = ISource.externalSource(builder.build(), true);

    // create the constraint set
    List<MetaConstraintSet.Context> contexts = ObjectUtils.notNull(constraints.getContextList().stream()
        .map(context -> parseContext(ObjectUtils.notNull(context), null, source))
        .collect(Collectors.toUnmodifiableList()));
    return CollectionUtil.singletonList(new MetaConstraintSet(source, importedConstraints, contexts));
  }

  private MetaConstraintSet.Context parseContext(
      @NonNull ModelContextType contextObj,
      @Nullable MetaConstraintSet.Context parent,
      @NonNull ISource source) {

    // generate the metapaths
    List<IMetapathExpression> metapaths = ObjectUtils.notNull(contextObj.getMetapathList().stream()
        .map(MetaschemaMetapathReferenceType::getTarget)
        .map(path -> IMetapathExpression.lazyCompile(ObjectUtils.notNull(path), source.getStaticContext()))
        .collect(Collectors.toList()));

    // parse the constraints
    IModelConstrained constraints = new AssemblyConstraintSet(source);
    ConstraintXmlSupport.parse(constraints, ObjectUtils.notNull(contextObj.getConstraints()), source);

    // create the context
    MetaConstraintSet.Context context = new MetaConstraintSet.Context(parent, source, metapaths, constraints);

    List<MetaConstraintSet.Context> childContexts = ObjectUtils.notNull(contextObj.getContextList().stream()
        .map(childObj -> parseContext(ObjectUtils.notNull(childObj), context, source))
        .collect(Collectors.toList()));

    context.addAll(childContexts);

    return context;
  }

  /**
   * Parse the provided XML resource as a Metaschema constraints.
   *
   * @param resource
   *          the resource to parse
   * @return the XMLBeans representation of the Metaschema contraints
   * @throws IOException
   *           if a parsing error occurred
   */
  @NonNull
  protected MetaschemaMetaConstraintsDocument parseConstraintSet(@NonNull URI resource) throws IOException {
    try {
      XmlOptions options = new XmlOptions();
      options.setBaseURI(resource);
      options.setLoadLineNumbers();
      return ObjectUtils.notNull(MetaschemaMetaConstraintsDocument.Factory.parse(resource.toURL(),
          options));
    } catch (XmlException ex) {
      throw new IOException(ex);
    }
  }
}
