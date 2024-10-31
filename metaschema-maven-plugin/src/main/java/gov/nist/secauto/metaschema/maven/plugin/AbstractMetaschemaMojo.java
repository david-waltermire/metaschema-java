/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.maven.plugin;

import gov.nist.secauto.metaschema.core.metapath.MetapathException;
import gov.nist.secauto.metaschema.core.model.IConstraintLoader;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.IResourceLocation;
import gov.nist.secauto.metaschema.core.model.MetaschemaException;
import gov.nist.secauto.metaschema.core.model.constraint.ConstraintValidationFinding;
import gov.nist.secauto.metaschema.core.model.constraint.ExternalConstraintsModulePostProcessor;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraintSet;
import gov.nist.secauto.metaschema.core.model.validation.AbstractValidationResultProcessor;
import gov.nist.secauto.metaschema.core.model.validation.IValidationFinding;
import gov.nist.secauto.metaschema.core.model.validation.IValidationResult;
import gov.nist.secauto.metaschema.core.model.validation.JsonSchemaContentValidator.JsonValidationFinding;
import gov.nist.secauto.metaschema.core.model.validation.XmlSchemaContentValidator.XmlValidationFinding;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.DefaultBindingContext;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.PostProcessingModuleLoaderStrategy;
import gov.nist.secauto.metaschema.databind.SimpleModuleLoaderStrategy;
import gov.nist.secauto.metaschema.databind.codegen.IGeneratedClass;
import gov.nist.secauto.metaschema.databind.codegen.IGeneratedModuleClass;
import gov.nist.secauto.metaschema.databind.codegen.IModuleBindingGenerator;
import gov.nist.secauto.metaschema.databind.codegen.IProduction;
import gov.nist.secauto.metaschema.databind.codegen.JavaCompilerSupport;
import gov.nist.secauto.metaschema.databind.codegen.JavaGenerator;
import gov.nist.secauto.metaschema.databind.codegen.ModuleCompilerHelper;
import gov.nist.secauto.metaschema.databind.codegen.config.DefaultBindingConfiguration;
import gov.nist.secauto.metaschema.databind.codegen.config.IBindingConfiguration;
import gov.nist.secauto.metaschema.databind.model.IBoundModule;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingMetaschemaModule;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingModuleLoader;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DependencyResolutionRequiredException;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.DirectoryScanner;
import org.sonatype.plexus.build.incremental.BuildContext;
import org.xml.sax.SAXParseException;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.tools.DiagnosticCollector;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public abstract class AbstractMetaschemaMojo
    extends AbstractMojo {
  private static final String[] DEFAULT_INCLUDES = { "**/*.xml" };

  /**
   * The Maven project context.
   *
   * @required
   * @readonly
   */
  @Parameter(defaultValue = "${project}", required = true, readonly = true)
  MavenProject mavenProject;

  /**
   * This will be injected if this plugin is executed as part of the standard
   * Maven lifecycle. If the mojo is directly invoked, this parameter will not be
   * injected.
   */
  @Parameter(defaultValue = "${mojoExecution}", readonly = true)
  private MojoExecution mojoExecution;

  @Component
  private BuildContext buildContext;

  @Parameter(defaultValue = "${plugin.artifacts}", readonly = true, required = true)
  private List<Artifact> pluginArtifacts;

  /**
   * <p>
   * The directory where the staleFile is found. The staleFile is used to
   * determine if re-generation of generated Java classes is needed, by recording
   * when the last build occurred.
   * </p>
   * <p>
   * This directory is expected to be located within the
   * <code>${project.build.directory}</code>, to ensure that code (re)generation
   * occurs after cleaning the project.
   * </p>
   */
  @Parameter(defaultValue = "${project.build.directory}/metaschema", readonly = true, required = true)
  protected File staleFileDirectory;

  /**
   * <p>
   * Defines the encoding used for generating Java Source files.
   * </p>
   * <p>
   * The algorithm for finding the encoding to use is as follows (where the first
   * non-null value found is used for encoding):
   * <ol>
   * <li>If the configuration property is explicitly given within the plugin's
   * configuration, use that value.</li>
   * <li>If the Maven property <code>project.build.sourceEncoding</code> is
   * defined, use its value.</li>
   * <li>Otherwise use the value from the system property
   * <code>file.encoding</code>.</li>
   * </ol>
   * </p>
   *
   * @see #getEncoding()
   * @since 2.0
   */
  @Parameter(defaultValue = "${project.build.sourceEncoding}")
  private String encoding;

  /**
   * Location to generate Java source files in.
   */
  @Parameter(defaultValue = "${project.build.directory}/generated-sources/metaschema", required = true)
  private File outputDirectory;

  /**
   * The directory to read source metaschema from.
   */
  @Parameter(defaultValue = "${basedir}/src/main/metaschema")
  private File metaschemaDir;

  /**
   * A list of <code>files</code> containing Metaschema module constraints files.
   */
  @Parameter(property = "constraints")
  private File[] constraints;

  /**
   * A set of inclusion patterns used to select which Metaschema modules are to be
   * processed. By default, all files are processed.
   */
  @Parameter
  protected String[] includes;

  /**
   * A set of exclusion patterns used to prevent certain files from being
   * processed. By default, this set is empty such that no files are excluded.
   */
  @Parameter
  protected String[] excludes;

  /**
   * Indicate if the execution should be skipped.
   */
  @Parameter(property = "metaschema.skip", defaultValue = "false")
  private boolean skip;

  /**
   * The BuildContext is used to identify which files or directories were modified
   * since last build. This is used to determine if Module-based generation must
   * be performed again.
   *
   * @return the active Plexus BuildContext.
   */
  protected final BuildContext getBuildContext() {
    return buildContext;
  }

  /**
   * Retrieve the Maven project context.
   *
   * @return The active MavenProject.
   */
  protected final MavenProject getMavenProject() {
    return mavenProject;
  }

  protected final List<Artifact> getPluginArtifacts() {
    return pluginArtifacts;
  }

  /**
   * Retrieve the mojo execution context.
   *
   * @return The active MojoExecution.
   */
  @SuppressFBWarnings(value = "EI_EXPOSE_REP", justification = "this is a data holder")
  public MojoExecution getMojoExecution() {
    return mojoExecution;
  }

  /**
   * Retrieve the directory where generated classes will be stored.
   *
   * @return the directory
   */
  protected File getOutputDirectory() {
    return outputDirectory;
  }

  /**
   * Set the directory where generated classes will be stored.
   *
   * @param outputDirectory
   *          the directory to use
   */
  protected void setOutputDirectory(File outputDirectory) {
    Objects.requireNonNull(outputDirectory, "outputDirectory");
    this.outputDirectory = outputDirectory;
  }

  /**
   * Gets the file encoding to use for generated classes.
   * <p>
   * The algorithm for finding the encoding to use is as follows (where the first
   * non-null value found is used for encoding):
   * </p>
   * <ol>
   * <li>If the configuration property is explicitly given within the plugin's
   * configuration, use that value.</li>
   * <li>If the Maven property <code>project.build.sourceEncoding</code> is
   * defined, use its value.</li>
   * <li>Otherwise use the value from the system property
   * <code>file.encoding</code>.</li>
   * </ol>
   *
   * @return The encoding to be used by this AbstractJaxbMojo and its tools.
   */
  protected final String getEncoding() {
    String encoding;
    if (this.encoding != null) {
      // first try to use the provided encoding
      encoding = this.encoding;
      if (getLog().isDebugEnabled()) {
        getLog().debug(String.format("Using configured encoding [%s].", encoding));
      }
    } else {
      encoding = Charset.defaultCharset().displayName();
      if (getLog().isWarnEnabled()) {
        getLog().warn(String.format("Using system encoding [%s]. This build is platform dependent!", encoding));
      }
    }
    return encoding;
  }

  /**
   * Retrieve a stream of Module file sources.
   *
   * @return the stream
   */
  protected Stream<File> getModuleSources() {
    DirectoryScanner ds = new DirectoryScanner();
    ds.setBasedir(metaschemaDir);
    ds.setIncludes(includes != null && includes.length > 0 ? includes : DEFAULT_INCLUDES);
    ds.setExcludes(excludes != null && excludes.length > 0 ? excludes : null);
    ds.addDefaultExcludes();
    ds.setCaseSensitive(true);
    ds.setFollowSymlinks(false);
    ds.scan();
    return Stream.of(ds.getIncludedFiles()).map(filename -> new File(metaschemaDir, filename)).distinct();
  }

  @NonNull
  protected IBindingContext newBindingContext() throws IOException, MetaschemaException {
    List<IConstraintSet> constraints = getConstraints();

    // generate Java sources based on provided metaschema sources
    return new DefaultBindingContext(
        new PostProcessingModuleLoaderStrategy(
            CollectionUtil.singletonList(new ExternalConstraintsModulePostProcessor(constraints)),
            new SimpleModuleLoaderStrategy(
                // this is used instead of the default generator to ensure that plugin classpath
                // entries are used for compilation
                new ModuleBindingGenerator(
                    ObjectUtils.notNull(Files.createDirectories(Paths.get("target/metaschema-codegen-modules"))),
                    new DefaultBindingConfiguration()))));
  }

  /**
   * Get the configured collection of constraints.
   *
   * @return the loaded constraints
   * @throws MetaschemaException
   *           if a binding exception occurred while loading the constraints
   * @throws IOException
   *           if an error occurred while reading the constraints
   */
  @NonNull
  protected List<IConstraintSet> getConstraints()
      throws MetaschemaException, IOException {
    IConstraintLoader loader = IBindingContext.getConstraintLoader();
    List<IConstraintSet> constraintSets = new ArrayList<>(constraints.length);
    for (File constraint : this.constraints) {
      constraintSets.addAll(loader.load(ObjectUtils.notNull(constraint)));
    }
    return CollectionUtil.unmodifiableList(constraintSets);
  }

  /**
   * Determine if the execution of this mojo should be skipped.
   *
   * @return {@code true} if the mojo execution should be skipped, or
   *         {@code false} otherwise
   */
  protected boolean shouldExecutionBeSkipped() {
    return skip;
  }

  /**
   * Get the name of the file that is used to detect staleness.
   *
   * @return the name
   */
  protected abstract String getStaleFileName();

  /**
   * Gets the staleFile for this execution.
   *
   * @return the staleFile
   */
  protected final File getStaleFile() {
    StringBuilder builder = new StringBuilder();
    if (getMojoExecution() != null) {
      builder.append(getMojoExecution().getExecutionId()).append('-');
    }
    builder.append(getStaleFileName());
    return new File(staleFileDirectory, builder.toString());
  }

  /**
   * Determine if code generation is required. This is done by comparing the last
   * modified time of each Module source file against the stale file managed by
   * this plugin.
   *
   * @return {@code true} if the code generation is needed, or {@code false}
   *         otherwise
   */
  protected boolean isGenerationRequired() {
    final File staleFile = getStaleFile();
    boolean generate = !staleFile.exists();
    if (generate) {
      if (getLog().isInfoEnabled()) {
        getLog().info(String.format("Stale file '%s' doesn't exist! Generating source files.", staleFile.getPath()));
      }
      generate = true;
    } else {
      generate = false;
      // check for staleness
      long staleLastModified = staleFile.lastModified();

      BuildContext buildContext = getBuildContext();
      URI metaschemaDirRelative = getMavenProject().getBasedir().toURI().relativize(metaschemaDir.toURI());

      if (buildContext.isIncremental() && buildContext.hasDelta(metaschemaDirRelative.toString())) {
        if (getLog().isInfoEnabled()) {
          getLog().info("metaschemaDirRelative: " + metaschemaDirRelative.toString());
        }
        generate = true;
      }

      if (!generate) {
        for (File sourceFile : getModuleSources().collect(Collectors.toList())) {
          if (getLog().isInfoEnabled()) {
            getLog().info("Source file: " + sourceFile.getPath());
          }
          if (sourceFile.lastModified() > staleLastModified) {
            generate = true;
          }
        }
      }
    }
    return generate;
  }

  protected Set<String> getClassPath() throws DependencyResolutionRequiredException {
    Set<String> pathElements;
    try {
      pathElements = new LinkedHashSet<>(getMavenProject().getCompileClasspathElements());
    } catch (DependencyResolutionRequiredException ex) {
      getLog().warn("exception calling getCompileClasspathElements", ex);
      throw ex;
    }

    if (pluginArtifacts != null) {
      for (Artifact a : getPluginArtifacts()) {
        if (a.getFile() != null) {
          pathElements.add(a.getFile().getAbsolutePath());
        }
      }
    }
    return pathElements;
  }

  @NonNull
  protected Set<IModule> getModulesToGenerateFor(@NonNull IBindingContext bindingContext)
      throws MetaschemaException, IOException {
    IBindingModuleLoader loader = bindingContext.newModuleLoader();
    loader.allowEntityResolution();

    LoggingValidationHandler validationHandler = new LoggingValidationHandler();

    Set<IModule> modules = new HashSet<>();
    for (File source : getModuleSources().collect(Collectors.toList())) {
      assert source != null;
      if (getLog().isInfoEnabled()) {
        getLog().info("Using metaschema source: " + source.getPath());
      }
      IBindingMetaschemaModule module = loader.load(source);

      IValidationResult result = bindingContext.validate(
          module.getSourceNodeItem(),
          loader.getBindingContext().newBoundLoader(),
          null);

      validationHandler.handleResults(result);

      modules.add(module);
    }
    return modules;
  }

  protected void createStaleFile(@NonNull File staleFile) throws MojoExecutionException {
    // create the stale file
    if (!staleFileDirectory.exists() && !staleFileDirectory.mkdirs()) {
      throw new MojoExecutionException("Unable to create output directory: " + staleFileDirectory);
    }
    try (OutputStream os
        = Files.newOutputStream(staleFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE,
            StandardOpenOption.TRUNCATE_EXISTING)) {
      os.close();
      if (getLog().isInfoEnabled()) {
        getLog().info("Created stale file: " + staleFile);
      }
    } catch (IOException ex) {
      throw new MojoExecutionException("Failed to write stale file: " + staleFile.getPath(), ex);
    }
  }

  protected final class LoggingValidationHandler
      extends AbstractValidationResultProcessor {

    private <T extends IValidationFinding> void handleFinding(
        @NonNull T finding,
        @NonNull Function<T, CharSequence> formatter) {

      Log log = getLog();

      switch (finding.getSeverity()) {
      case CRITICAL:
      case ERROR:
        if (log.isErrorEnabled()) {
          log.error(formatter.apply(finding), finding.getCause());
        }
        break;
      case WARNING:
        if (log.isWarnEnabled()) {
          getLog().warn(formatter.apply(finding), finding.getCause());
        }
        break;
      case INFORMATIONAL:
        if (log.isInfoEnabled()) {
          getLog().info(formatter.apply(finding), finding.getCause());
        }
        break;
      default:
        if (log.isDebugEnabled()) {
          getLog().debug(formatter.apply(finding), finding.getCause());
        }
        break;
      }
    }

    @Override
    protected void handleJsonValidationFinding(JsonValidationFinding finding) {
      handleFinding(finding, this::getMessage);
    }

    @Override
    protected void handleXmlValidationFinding(XmlValidationFinding finding) {
      handleFinding(finding, this::getMessage);
    }

    @Override
    protected void handleConstraintValidationFinding(ConstraintValidationFinding finding) {
      handleFinding(finding, this::getMessage);
    }

    @NonNull
    private CharSequence getMessage(JsonValidationFinding finding) {
      StringBuilder builder = new StringBuilder();
      builder.append('[')
          .append(finding.getCause().getPointerToViolation())
          .append("] ")
          .append(finding.getMessage());

      URI documentUri = finding.getDocumentUri();
      if (documentUri != null) {
        builder.append(" [")
            .append(documentUri.toString())
            .append(']');
      }
      return builder;
    }

    @NonNull
    private CharSequence getMessage(XmlValidationFinding finding) {
      StringBuilder builder = new StringBuilder();

      builder.append(finding.getMessage())
          .append(" [");

      URI documentUri = finding.getDocumentUri();
      if (documentUri != null) {
        builder.append(documentUri.toString());
      }

      SAXParseException ex = finding.getCause();
      builder.append(finding.getMessage())
          .append('{')
          .append(ex.getLineNumber())
          .append(',')
          .append(ex.getColumnNumber())
          .append("}]");
      return builder;
    }

    @NonNull
    private CharSequence getMessage(@NonNull ConstraintValidationFinding finding) {
      StringBuilder builder = new StringBuilder();
      builder.append('[')
          .append(finding.getTarget().getMetapath())
          .append(']');

      String id = finding.getIdentifier();
      if (id != null) {
        builder.append(' ')
            .append(id);
      }

      builder.append(' ')
          .append(finding.getMessage());

      URI documentUri = finding.getTarget().getBaseUri();
      IResourceLocation location = finding.getLocation();
      if (documentUri != null || location != null) {
        builder.append(" [");
      }

      if (documentUri != null) {
        builder.append(documentUri.toString());
      }

      if (location != null) {
        builder.append('{')
            .append(location.getLine())
            .append(',')
            .append(location.getColumn())
            .append('}');
      }
      if (documentUri != null || location != null) {
        builder.append(']');
      }
      return builder;
    }
  }

  public class ModuleBindingGenerator implements IModuleBindingGenerator {
    @NonNull
    private final Path compilePath;
    @NonNull
    private final ClassLoader classLoader;
    @NonNull
    private final IBindingConfiguration bindingConfiguration;

    public ModuleBindingGenerator(
        @NonNull Path compilePath,
        @NonNull IBindingConfiguration bindingConfiguration) {
      this.compilePath = compilePath;
      this.classLoader = ModuleCompilerHelper.newClassLoader(
          compilePath,
          ObjectUtils.notNull(Thread.currentThread().getContextClassLoader()));
      this.bindingConfiguration = bindingConfiguration;
    }

    @NonNull
    public IProduction generateClasses(@NonNull IModule module) {
      IProduction production;
      try {
        production = JavaGenerator.generate(module, compilePath, bindingConfiguration);
      } catch (IOException ex) {
        throw new MetapathException(
            String.format("Unable to generate and compile classes for module '%s'.", module.getLocation()),
            ex);
      }
      return production;
    }

    public void compileClasses(@NonNull IProduction production, @NonNull Path classDir)
        throws IOException, DependencyResolutionRequiredException {
      List<IGeneratedClass> classesToCompile = production.getGeneratedClasses().collect(Collectors.toList());

      List<Path> classes = ObjectUtils.notNull(classesToCompile.stream()
          .map(IGeneratedClass::getClassFile)
          .collect(Collectors.toUnmodifiableList()));

      JavaCompilerSupport compiler = new JavaCompilerSupport(classDir);

      getClassPath().forEach(compiler::addToClassPath);

      JavaCompilerSupport.CompilationResult result = compiler.compile(classes, null);

      if (!result.isSuccessful()) {
        DiagnosticCollector<?> diagnostics = new DiagnosticCollector<>();
        if (getLog().isErrorEnabled()) {
          getLog().error("diagnostics: " + diagnostics.getDiagnostics().toString());
        }
        throw new IllegalStateException(String.format("failed to compile classes: %s",
            classesToCompile.stream()
                .map(clazz -> clazz.getClassName().canonicalName())
                .collect(Collectors.joining(","))));
      }
    }

    @Override
    public Class<? extends IBoundModule> generate(IModule module) {
      IProduction production = generateClasses(module);
      try {
        compileClasses(production, compilePath);
      } catch (IOException | DependencyResolutionRequiredException ex) {
        throw new IllegalStateException("failed to compile classes", ex);
      }
      IGeneratedModuleClass moduleClass = ObjectUtils.requireNonNull(production.getModuleProduction(module));

      try {
        return moduleClass.load(classLoader);
      } catch (ClassNotFoundException ex) {
        throw new IllegalStateException(ex);
      }
    }

  }
}
