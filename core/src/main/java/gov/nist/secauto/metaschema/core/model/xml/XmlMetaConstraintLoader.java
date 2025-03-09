/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.xml;

import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression;
import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.model.AbstractLoader;
import gov.nist.secauto.metaschema.core.model.IConstraintLoader;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.constraint.AssemblyConstraintSet;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraintSet;
import gov.nist.secauto.metaschema.core.model.constraint.IModelConstrained;
import gov.nist.secauto.metaschema.core.model.constraint.ITargetedConstraints;
import gov.nist.secauto.metaschema.core.model.constraint.ModelTargetedConstraints;
import gov.nist.secauto.metaschema.core.model.xml.impl.ConstraintXmlSupport;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.MetaschemaMetaConstraintsDocument;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.MetaschemaMetapathReferenceType;
import gov.nist.secauto.metaschema.core.model.xml.xmlbeans.ModelContextType;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlOptions;

import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.Deque;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Used to load a set of external constraints from an XML-based resource.
 */
@SuppressWarnings("PMD.CouplingBetweenObjects")
public class XmlMetaConstraintLoader
    extends AbstractLoader<List<IConstraintSet>>
    implements IConstraintLoader {

  @Override
  protected List<IConstraintSet> parseResource(URI resource, Deque<URI> visitedResources) throws IOException {

    // parse this metaschema
    MetaschemaMetaConstraintsDocument xmlObject = parseConstraintSet(resource);

    MetaschemaMetaConstraintsDocument.MetaschemaMetaConstraints constraints = xmlObject.getMetaschemaMetaConstraints();

    StaticContext.Builder builder = StaticContext.builder()
        .baseUri(resource);

    constraints.getNamespaceBindingList().stream()
        .forEach(binding -> builder.namespace(
            ObjectUtils.notNull(binding.getPrefix()), ObjectUtils.notNull(binding.getUri())));
    builder.useWildcardWhenNamespaceNotDefaulted(true);

    ISource source = ISource.externalSource(builder.build(), true);

    List<ITargetedConstraints> targetedConstraints = ObjectUtils.notNull(constraints.getContextList().stream()
        .flatMap(context -> parseContext(ObjectUtils.notNull(context), null, source).getTargetedConstraints().stream())
        .collect(Collectors.toList()));
    return CollectionUtil.singletonList(new MetaConstraintSet(source, targetedConstraints));
  }

  private Context parseContext(
      @NonNull ModelContextType contextObj,
      @Nullable Context parent,
      @NonNull ISource source) {

    List<String> metapaths;
    if (parent == null) {
      metapaths = ObjectUtils.notNull(contextObj.getMetapathList().stream()
          .map(MetaschemaMetapathReferenceType::getTarget)
          .collect(Collectors.toList()));
    } else {
      List<String> parentMetapaths = parent.getMetapaths().stream()
          .collect(Collectors.toList());
      metapaths = ObjectUtils.notNull(contextObj.getMetapathList().stream()
          .map(MetaschemaMetapathReferenceType::getTarget)
          .flatMap(childPath -> parentMetapaths.stream()
              .map(parentPath -> parentPath + '/' + childPath))
          .collect(Collectors.toList()));
    }

    IModelConstrained constraints = new AssemblyConstraintSet(source);
    ConstraintXmlSupport.parse(constraints, ObjectUtils.notNull(contextObj.getConstraints()), source);
    Context context = new Context(source, metapaths, constraints);

    List<Context> childContexts = contextObj.getContextList().stream()
        .map(childObj -> parseContext(ObjectUtils.notNull(childObj), context, source))
        .collect(Collectors.toList());

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

  private static class Context {
    @NonNull
    private final ISource source;
    @NonNull
    private final List<String> metapaths;
    @NonNull
    private final IModelConstrained constraints;
    @NonNull
    private final List<Context> childContexts = new LinkedList<>();

    public Context(
        @NonNull ISource source,
        @NonNull List<String> metapaths,
        @NonNull IModelConstrained constraints) {
      this.source = source;
      this.metapaths = metapaths;
      this.constraints = constraints;
    }

    public List<ITargetedConstraints> getTargetedConstraints() {
      return Stream.concat(
          getMetapaths().stream()
              .map(metapath -> new ModelTargetedConstraints(
                  source,
                  IMetapathExpression.lazyCompile(
                      ObjectUtils.requireNonNull(metapath),
                      source.getStaticContext()),
                  constraints)),
          childContexts.stream()
              .flatMap(child -> child.getTargetedConstraints().stream()))
          .collect(Collectors.toList());
    }

    public void addAll(Collection<Context> childContexts) {
      childContexts.addAll(childContexts);
    }

    public List<String> getMetapaths() {
      return metapaths;
    }
  }

  private static final class MetaConstraintSet implements IConstraintSet {
    @NonNull
    private final ISource source;
    @NonNull
    private final List<ITargetedConstraints> targetedConstraints;

    private MetaConstraintSet(
        @NonNull ISource source,
        @NonNull List<ITargetedConstraints> targetedConstraints) {
      this.source = source;
      this.targetedConstraints = targetedConstraints;
    }

    @Override
    public ISource getSource() {
      return source;
    }

    @Override
    public Iterable<ITargetedConstraints> getTargetedConstraintsForModule(IModule module) {
      return targetedConstraints;
    }

    @Override
    public Collection<IConstraintSet> getImportedConstraintSets() {
      return CollectionUtil.emptyList();
    }

  }
}
