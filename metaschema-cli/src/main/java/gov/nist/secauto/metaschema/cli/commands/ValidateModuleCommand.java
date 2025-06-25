/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.cli.commands;

import gov.nist.secauto.metaschema.cli.processor.CLIProcessor.CallingContext;
import gov.nist.secauto.metaschema.cli.processor.ExitCode;
import gov.nist.secauto.metaschema.cli.processor.command.CommandExecutionException;
import gov.nist.secauto.metaschema.cli.processor.command.ICommandExecutor;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.MetaschemaException;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraintSet;
import gov.nist.secauto.metaschema.core.model.util.JsonUtil;
import gov.nist.secauto.metaschema.core.model.validation.JsonSchemaContentValidator;
import gov.nist.secauto.metaschema.core.model.validation.XmlSchemaContentValidator;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.IBindingContext.ISchemaValidationProvider;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.MetaschemaModelModule;

import org.apache.commons.cli.CommandLine;
import org.json.JSONObject;
import org.xml.sax.SAXException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * This command implementation supports validation a Metaschema module.
 */
class ValidateModuleCommand
    extends AbstractValidateContentCommand {
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
    return new CommandExecutor(callingContext, commandLine);
  }

  private final class CommandExecutor
      extends AbstractValidationCommandExecutor {
    private final Lazy<ValidationProvider> validationProvider = Lazy.of(ValidationProvider::new);

    private CommandExecutor(
        @NonNull CallingContext callingContext,
        @NonNull CommandLine commandLine) {
      super(callingContext, commandLine);
    }

    @Override
    protected IBindingContext getBindingContext(Set<IConstraintSet> constraintSets)
        throws CommandExecutionException {
      return MetaschemaCommands.newBindingContextWithDynamicCompilation(constraintSets);
    }

    @Override
    protected IModule getModule(CommandLine commandLine, IBindingContext bindingContext)
        throws CommandExecutionException {
      try {
        return bindingContext.registerModule(MetaschemaModelModule.class);
      } catch (MetaschemaException ex) {
        throw new CommandExecutionException(ExitCode.PROCESSING_ERROR, ex);
      }
    }

    @Override
    protected ISchemaValidationProvider getSchemaValidationProvider(
        IModule module,
        CommandLine commandLine,
        IBindingContext bindingContext) {
      // ignore the arguments and return the pre-generated schema provider
      return ObjectUtils.notNull(validationProvider.get());
    }
  }

  private static final class ValidationProvider implements ISchemaValidationProvider {
    @SuppressWarnings("resource")
    @Override
    public XmlSchemaContentValidator getXmlSchemas(
        @NonNull URL targetResource,
        @NonNull IBindingContext bindingContext) throws IOException, SAXException {
      try (InputStream is = this.getClass().getResourceAsStream("/schema/xml/metaschema-model_schema.xsd")) {
        List<Source> sources = new LinkedList<>();
        sources.add(new StreamSource(
            ObjectUtils.requireNonNull(is,
                "Unable to load '/schema/xml/metaschema.xsd' on the classpath")));
        return new XmlSchemaContentValidator(sources);
      }
    }

    @Override
    public JsonSchemaContentValidator getJsonSchema(
        @NonNull JSONObject json,
        @NonNull IBindingContext bindingContext) throws IOException {
      try (BufferedReader reader = new BufferedReader(
          new InputStreamReader(
              this.getClass().getResourceAsStream("/schema/json/metaschema-model_schema.json"),
              StandardCharsets.UTF_8))) {
        return new JsonSchemaContentValidator(JsonUtil.toJsonObject(reader));
      }
    }
  }
}
