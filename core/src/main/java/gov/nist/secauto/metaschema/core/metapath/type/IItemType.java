/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type;

import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IAssemblyNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDocumentNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IFieldNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IFlagNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IModuleNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.metapath.type.impl.AnyFunctionItemType;
import gov.nist.secauto.metaschema.core.metapath.type.impl.AnyItemType;
import gov.nist.secauto.metaschema.core.metapath.type.impl.AnyKindTest;
import gov.nist.secauto.metaschema.core.metapath.type.impl.ArrayTestImpl;
import gov.nist.secauto.metaschema.core.metapath.type.impl.KindAssemblyTestImpl;
import gov.nist.secauto.metaschema.core.metapath.type.impl.KindDocumentTestImpl;
import gov.nist.secauto.metaschema.core.metapath.type.impl.KindFieldTestImpl;
import gov.nist.secauto.metaschema.core.metapath.type.impl.KindFlagTestImpl;
import gov.nist.secauto.metaschema.core.metapath.type.impl.MapTestImpl;
import gov.nist.secauto.metaschema.core.metapath.type.impl.TypeConstants;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Provides type information that be used to discover type information for,
 * test, and cast various item objects.
 * <p>
 * A variety of static methods are provided that can be used to generate tests
 * that compare an item's actual type against an expectation.
 */
public interface IItemType {
  /**
   * Get a new kind test that matches any item.
   *
   * @return the test
   */
  @NonNull
  static IItemType item() {
    return AnyItemType.instance();
  }

  /**
   * Get a new kind test that matches any function item.
   *
   * @return the function test
   */
  @NonNull
  static IItemType function() {
    return AnyFunctionItemType.ANY_FUNCTION;
  }

  // static IFunctionTest function(@NonNull ISequenceType result, @NonNull
  // ISequenceType... args) {
  //
  // }

  /**
   * Get a new kind test that matches any map item.
   *
   * @return the map test
   */
  @NonNull
  static IItemType map() {
    return AnyFunctionItemType.ANY_MAP;
  }

  /**
   * Get a new kind test that matches any map item whose keys and values match the
   * provided atomic type and sequence type respectively.
   *
   * @param key
   *          the expected atomic type of the map's key
   * @param value
   *          the sequence test to use to check the map's contents
   *
   * @return the map test
   */
  @NonNull
  static IMapTest map(@NonNull IAtomicOrUnionType<?> key, @NonNull ISequenceType value) {
    return new MapTestImpl(key, value);
  }

  /**
   * Get a new kind test that matches any array item whose values match the
   * provided sequence.
   *
   * @return the array test
   */
  @NonNull
  static IItemType array() {
    return AnyFunctionItemType.ANY_ARRAY;
  }

  /**
   * Get a new kind test that matches any array item whose values match the
   * provided sequence.
   *
   * @param value
   *          the sequence test to use to check the array's contents
   *
   * @return the array test
   */
  @NonNull
  static IItemType array(@NonNull ISequenceType value) {
    return new ArrayTestImpl(value);
  }

  /**
   * Get a new kind test that matches any atomic valued item.
   *
   * @return the atomic type test
   */
  @NonNull
  static IAtomicOrUnionType<?> anyAtomic() {
    return TypeConstants.ANY_ATOMIC_TYPE;
  }

  /**
   * Get a new kind test that matches any {@link INodeItem}.
   *
   * @return the node kind test
   */
  @NonNull
  static IKindTest<INodeItem> node() {
    return AnyKindTest.ANY_NODE;
  }

  /**
   * Get a new kind test that matches any Metaschema {@link IModuleNodeItem}.
   *
   * @return the module kind test
   */
  @NonNull
  static IKindTest<IModuleNodeItem> module() {
    return AnyKindTest.ANY_MODULE;
  }

  /**
   * Get a new kind test that matches any {@link IDocumentNodeItem}.
   *
   * @return the document kind test
   */
  @NonNull
  static IKindTest<IDocumentNodeItem> document() {
    return AnyKindTest.ANY_DOCUMENT;
  }

  /**
   * Get a new kind test that that matches an {@link IDocumentNodeItem} that has a
   * root node of the provided kind.
   *
   * @param test
   *          the root node test
   * @return the document kind test
   */
  @NonNull
  static IKindTest<IDocumentNodeItem> document(@NonNull IKindTest<IAssemblyNodeItem> test) {
    return new KindDocumentTestImpl(test);
  }

  /**
   * Matches any {@link IAssemblyNodeItem} regardless of its name or type.
   *
   * @return the test
   */
  @NonNull
  static IKindTest<IAssemblyNodeItem> assembly() {
    return AnyKindTest.ANY_ASSEMBLY;
  }

  /**
   * Get a new kind test that matches a {@link IAssemblyNodeItem} with the
   * provided name and a type matching the provided name of a specific assembly
   * definition.
   * <p>
   * If used as part of a document kind test, the the provided
   * {@code instanceName} will match the root assembly name of the document's
   * root.
   *
   * @param instanceName
   *          the name of the assembly root definition or instance to match
   *          depending on the use context
   * @param typeName
   *          the name of the assembly definition to match
   * @param staticContext
   *          the static context in which the test was declared
   * @return the test
   */
  @NonNull
  static IKindTest<IAssemblyNodeItem> assembly(
      @NonNull IEnhancedQName instanceName,
      @Nullable String typeName,
      @NonNull StaticContext staticContext) {
    return new KindAssemblyTestImpl(instanceName, typeName, staticContext);
  }

  /**
   * Get a new kind test that matches an {@link IAssemblyNodeItem} with any name
   * and a type matching the provided name of a specific assembly definition.
   *
   * @param typeName
   *          the name of the assembly definition to match
   * @param staticContext
   *          the static context in which the test was declared
   * @return the test
   */
  @NonNull
  static IKindTest<IAssemblyNodeItem> assembly(
      @NonNull String typeName,
      @NonNull StaticContext staticContext) {
    return new KindAssemblyTestImpl(null, typeName, staticContext);
  }

  /**
   * Matches any {@link IFieldNodeItem} regardless of its name or type.
   *
   * @return the test
   */
  @NonNull
  static IKindTest<IFieldNodeItem> field() {
    return AnyKindTest.ANY_FIELD;
  }

  /**
   * Matches any {@link IFieldNodeItem} with the provided name and a type matching
   * the provided name of a specific field definition.
   *
   * @param instanceName
   *          the name of the field instance to match depending on the use context
   * @param typeName
   *          the name of the field definition to match
   * @param staticContext
   *          the static context in which the test was declared
   * @return the test
   */
  @NonNull
  static IKindTest<IFieldNodeItem> field(
      @NonNull IEnhancedQName instanceName,
      @Nullable String typeName,
      @NonNull StaticContext staticContext) {
    return new KindFieldTestImpl(instanceName, typeName, staticContext);
  }

  /**
   * Matches any {@link IFieldNodeItem} with a name and type matching the provided
   * name of a specific field definition.
   *
   * @param typeName
   *          the name of the field definition to match
   * @param staticContext
   *          the static context in which the test was declared
   * @return the test
   */
  @NonNull
  static IKindTest<IFieldNodeItem> field(@NonNull String typeName, @NonNull StaticContext staticContext) {
    return new KindFieldTestImpl(null, typeName, staticContext);
  }

  /**
   * Matches any {@link IFlagNodeItem} regardless of its name or type.
   *
   * @return the test
   */
  @NonNull
  static IKindTest<IFlagNodeItem> flag() {
    return AnyKindTest.ANY_FLAG;
  }

  /**
   * Matches any {@link IFlagNodeItem} with the provided name and type matching
   * the provided name of a specific globally-scoped flag definition.
   *
   * @param instanceName
   *          the name of the flag instance to match
   * @param typeName
   *          the name of the flag definition or value type to match
   * @param staticContext
   *          the static context in which the test was declared
   * @return the test
   */
  @NonNull
  static IKindTest<IFlagNodeItem> flag(
      @NonNull IEnhancedQName instanceName,
      @Nullable String typeName,
      @NonNull StaticContext staticContext) {
    return new KindFlagTestImpl(instanceName, typeName, staticContext);
  }

  /**
   * Matches any {@link IFlagNodeItem} with any name and type matching the
   * provided name of a specific globally-scoped flag definition.
   *
   * @param typeName
   *          the name of the globally-scoped flag definition to match
   * @param staticContext
   *          the static context in which the test was declared
   * @return the test
   */
  @NonNull
  static IKindTest<IFlagNodeItem> flag(@NonNull String typeName, @NonNull StaticContext staticContext) {
    return new KindFlagTestImpl(null, typeName, staticContext);
  }

  /**
   * Test if the provided item matches this item type.
   *
   * @param item
   *          the item to test
   * @return {@code true} if the item matches the expectations or {@code false}
   *         otherwise
   */
  default boolean isInstance(IItem item) {
    return getItemClass().isInstance(item);
  }

  /**
   * Cast the provided item to the expected type.
   * <p>
   * If Java assertions are enabled, this method will check that the provided item
   * is an instance of this type. As a result, this method is not a rigorous as
   * the {@link #test(IItem)} method, which always checks that the item matches
   * the type. However, this method can be used where it is certain that the type
   * matches, perhaps because the type has been previously checked.
   *
   * @param <T>
   *          the expected Java type of the item
   * @param item
   *          the item to cast
   * @return the item cast to the expected type
   * @throws ClassCastException
   *           if the item's Java type is not a subclass of the expected type
   * @throws AssertionError
   *           if the item is not an instance of this type
   */
  @SuppressWarnings("unchecked")
  @NonNull
  default <T extends IItem> T ofType(@Nullable IItem item) {
    assert item != null && isInstance(item);

    return (T) item;
  }

  /**
   * Cast the provided item to the expected type.
   * <p>
   * If Java assertions are enabled, this method will check that the provided item
   * is an instance of this type or {@code null}. As a result, this method is not
   * a rigorous as the {@link #testOrNull(IItem)} method, which always checks that
   * the item matches the type. However, this method can be used where it is
   * certain that the type matches, perhaps because the type has been previously
   * checked.
   *
   * @param <T>
   *          the expected Java type of the item
   * @param item
   *          the item to cast
   * @return the item, which may be {@code null} cast to the expected type
   * @throws ClassCastException
   *           if the item's Java type is not a subclass of the expected type
   * @throws AssertionError
   *           if the item is not an instance of this type
   */
  @SuppressWarnings("unchecked")
  @Nullable
  default <T extends IItem> T ofTypeOrNull(@Nullable IItem item) {
    assert item == null || isInstance(item);

    return (T) item;
  }

  /**
   * Test if the provided item matches this item type.
   *
   * @param <T>
   *          the Java type of the item tested
   * @param item
   *          the item to test
   * @return the item if the test passes
   * @throws InvalidTypeMetapathException
   *           if the test fails because the item is not the required type
   */
  @SuppressWarnings("unchecked")
  @NonNull
  default <T extends IItem> T test(@Nullable IItem item) {
    if (item != null && isInstance(item)) {
      return (T) item;
    }
    throw new InvalidTypeMetapathException(
        null,
        String.format("The item '%s' is not a '%s'",
            item == null ? "null" : item.toSignature(),
            toSignature()));
  }

  /**
   * Test if the provided item matches this item type.
   *
   * @param <T>
   *          the Java type of the item tested
   * @param item
   *          the item to test
   * @return the item if the test passes
   * @throws InvalidTypeMetapathException
   *           if the test fails because the item is not the required type
   */
  @SuppressWarnings("unchecked")
  @Nullable
  default <T extends IItem> T testOrNull(@Nullable IItem item) {
    if (item == null || isInstance(item)) {
      return (T) item;
    }
    throw new InvalidTypeMetapathException(
        null,
        String.format("The item '%s' is not a '%s'",
            item.toSignature(),
            toSignature()));
  }

  /**
   * Get the item Java class associated with this item type.
   *
   * @return the item Java class
   */
  @NonNull
  Class<? extends IItem> getItemClass();

  /**
   * Get the human-readable signature of the item type.
   *
   * @return the signature
   */
  @NonNull
  String toSignature();
}
