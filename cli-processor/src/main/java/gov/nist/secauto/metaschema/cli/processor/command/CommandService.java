/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.cli.processor.command;

import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.List;
import java.util.ServiceLoader;
import java.util.ServiceLoader.Provider;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * A service that loads commands using SPI.
 * <p>
 * This class implements the singleton pattern to ensure a single instance of
 * the command service is used throughout the application.
 *
 * @see ServiceLoader for more information
 */
public final class CommandService {
  private static final Lazy<CommandService> INSTANCE = Lazy.of(CommandService::new);
  @NonNull
  private final ServiceLoader<ICommand> loader;

  /**
   * Get the singleton instance of the function service.
   *
   * @return the service instance
   */
  public static CommandService getInstance() {
    return INSTANCE.get();
  }

  /**
   * Construct a new service.
   * <p>
   * Initializes the ServiceLoader for ICommand implementations.
   * <p>
   * This constructor is private to enforce the singleton pattern.
   */
  private CommandService() {
    ServiceLoader<ICommand> loader = ServiceLoader.load(ICommand.class);
    assert loader != null;
    this.loader = loader;
  }

  /**
   * Get the function service loader instance.
   *
   * @return the service loader instance.
   */
  @NonNull
  private ServiceLoader<ICommand> getLoader() {
    return loader;
  }

  /**
   * Get the loaded commands.
   *
   * @return the list of loaded commands
   */
  @NonNull
  public List<ICommand> getCommands() {
    return ObjectUtils.notNull(getLoader().stream()
        .map(Provider<ICommand>::get)
        .collect(Collectors.toUnmodifiableList()));
  }
}
