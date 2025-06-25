/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function;

import gov.nist.secauto.metaschema.core.metapath.StaticMetapathException;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.ServiceLoader;
import java.util.ServiceLoader.Provider;
import java.util.stream.Stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import nl.talsmasoftware.lazy4j.Lazy;

/**
 * Supports looking up named Metapath functions that are loaded using the
 * {@link ServiceLoader} interface.
 */
public final class FunctionService implements IFunctionResolver {
  private static final Lazy<FunctionService> INSTANCE = Lazy.of(FunctionService::new);
  @NonNull
  private final ServiceLoader<IFunctionLibrary> loader;
  @NonNull
  private final Lazy<IFunctionLibrary> library;

  /**
   * Get the singleton instance of the function service.
   *
   * @return the service instance
   */
  // FIXME: rename to instance()
  @NonNull
  public static FunctionService getInstance() {
    return ObjectUtils.notNull(INSTANCE.get());
  }

  /**
   * Construct a new function service.
   */
  @SuppressWarnings("null")
  public FunctionService() {
    this.loader = ServiceLoader.load(IFunctionLibrary.class);
    ServiceLoader<IFunctionLibrary> loader = getLoader();

    this.library = Lazy.of(() -> {
      FunctionLibrary functionLibrary = new FunctionLibrary();
      loader.stream()
          .map(Provider<IFunctionLibrary>::get)
          .flatMap(IFunctionLibrary::stream)
          .forEachOrdered(function -> functionLibrary.registerFunction(ObjectUtils.notNull(function)));
      return functionLibrary;
    });
  }

  /**
   * Get the function service loader instance.
   *
   * @return the service loader instance.
   */
  @NonNull
  private ServiceLoader<IFunctionLibrary> getLoader() {
    return loader;
  }

  @NonNull
  private IFunctionLibrary getLibrary() {
    return ObjectUtils.notNull(library.get());
  }

  /**
   * Retrieve the collection of function signatures in this library as a stream.
   *
   * @return a stream of function signatures
   */
  @NonNull
  public Stream<IFunction> stream() {
    return getLibrary().stream();
  }

  @Override
  public IFunction getFunction(@NonNull IEnhancedQName name, int arity) {
    IFunction retval = getLibrary().getFunction(name, arity);

    if (retval == null) {
      throw new StaticMetapathException(StaticMetapathException.NO_FUNCTION_MATCH,
          String.format("unable to find function with name '%s' having arity '%d'", name, arity));
    }
    return retval;
  }
}
