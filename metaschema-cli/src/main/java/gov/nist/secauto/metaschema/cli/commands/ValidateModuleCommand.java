/*
 * Portions of this software was developed by employees of the National Institute
 * of Standards and Technology (NIST), an agency of the Federal Government and is
 * being made available as a public service. Pursuant to title 17 United States
 * Code Section 105, works of NIST employees are not subject to copyright
 * protection in the United States. This software may be subject to foreign
 * copyright. Permission in the United States and in foreign countries, to the
 * extent that NIST may hold copyright, to use, copy, modify, create derivative
 * works, and distribute this software and its documentation without fee is hereby
 * granted on a non-exclusive basis, provided that this notice and disclaimer
 * of warranty appears in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, EITHER
 * EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY
 * THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM
 * INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE
 * SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT
 * SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT,
 * INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM,
 * OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY,
 * CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR
 * PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT
 * OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER.
 */

package gov.nist.secauto.metaschema.cli.commands;

import gov.nist.secauto.metaschema.cli.processor.CLIProcessor.CallingContext;
import gov.nist.secauto.metaschema.cli.processor.command.ICommandExecutor;
import gov.nist.secauto.metaschema.core.configuration.DefaultConfiguration;
import gov.nist.secauto.metaschema.core.configuration.IMutableConfiguration;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.MetaschemaException;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraintSet;
import gov.nist.secauto.metaschema.core.model.util.JsonUtil;
import gov.nist.secauto.metaschema.core.model.util.XmlUtil;
import gov.nist.secauto.metaschema.core.model.xml.ExternalConstraintsModulePostProcessor;
import gov.nist.secauto.metaschema.core.model.xml.ModuleLoader;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.DefaultBindingContext;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.model.binding.metaschema.METASCHEMA;
import gov.nist.secauto.metaschema.databind.model.binding.metaschema.MetaschemaModelModule;
import gov.nist.secauto.metaschema.schemagen.ISchemaGenerator;
import gov.nist.secauto.metaschema.schemagen.ISchemaGenerator.SchemaFormat;
import gov.nist.secauto.metaschema.schemagen.SchemaGenerationFeature;

import org.apache.commons.cli.CommandLine;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.xml.transform.Source;

import edu.umd.cs.findbugs.annotations.NonNull;

public class ValidateModuleCommand
    extends AbstractValidateContentCommand {
  private static final Logger LOGGER = LogManager.getLogger(ValidateModuleCommand.class);
  @NonNull
  private static final String COMMAND = "validate";

  @Override
  public String getName() {
    return COMMAND;
  }

  @Override
  public String getDescription() {
    return "Validate that the specified Module is well-formed and valid to the Module model";
  }

  @Override
  public ICommandExecutor newExecutor(CallingContext callingContext, CommandLine commandLine) {
    return new ValidateModuleCommandExecutor(callingContext, commandLine);
  }

  private final class ValidateModuleCommandExecutor
      extends AbstractValidationCommandExecutor {
    private Path tempDir;

    private ValidateModuleCommandExecutor(
        @NonNull CallingContext callingContext,
        @NonNull CommandLine commandLine) {
      super(callingContext, commandLine);
    }

    private Path getTempDir() throws IOException {
      if (tempDir == null) {
        tempDir = Files.createTempDirectory("validation-");
        tempDir.toFile().deleteOnExit();
      }
      return tempDir;
    }

    @Override
    protected IBindingContext getBindingContext(Set<IConstraintSet> constraintSets)
        throws MetaschemaException, IOException {
      IBindingContext retval;
      if (constraintSets.isEmpty()) {
        retval = IBindingContext.instance();
      } else {
        ExternalConstraintsModulePostProcessor postProcessor
            = new ExternalConstraintsModulePostProcessor(constraintSets);
        retval = new DefaultBindingContext(CollectionUtil.singletonList(postProcessor));
      }
      retval.getBoundDefinitionForClass(METASCHEMA.class);
      return retval;
    }

    @Override
    public List<Source> getXmlSchemas(@NonNull URL targetResource) throws IOException {
      List<Source> retval = new LinkedList<>();
      retval.add(XmlUtil.getStreamSource(
          ObjectUtils.requireNonNull(
              ModuleLoader.class.getResource("/schema/xml/metaschema.xsd"),
              "Unable to load '/schema/xml/metaschema.xsd' on the classpath")));
      return CollectionUtil.unmodifiableList(retval);
    }

    @Override
    public JSONObject getJsonSchema(@NonNull JSONObject json) throws IOException {
      IModule module = IBindingContext.instance().registerModule(MetaschemaModelModule.class);

      Path schemaFile = Files.createTempFile(getTempDir(), "schema-", ".json");
      assert schemaFile != null;
      IMutableConfiguration<SchemaGenerationFeature<?>> configuration = new DefaultConfiguration<>();
      ISchemaGenerator.generateSchema(module, schemaFile, SchemaFormat.JSON, configuration);
      try (BufferedReader reader = ObjectUtils.notNull(Files.newBufferedReader(schemaFile, StandardCharsets.UTF_8))) {
        return JsonUtil.toJsonObject(reader);
      }
    }
  }
}
