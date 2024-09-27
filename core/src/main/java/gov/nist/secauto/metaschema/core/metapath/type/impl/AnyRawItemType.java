
package gov.nist.secauto.metaschema.core.metapath.type.impl;

import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapItem;

import edu.umd.cs.findbugs.annotations.NonNull;

public final class AnyRawItemType<I extends IItem>
    extends AbstractItemType<I> {
  public static final AnyRawItemType<IFunction> ANY_FUNCTION = new AnyRawItemType<>(
      IFunction.class,
      "function(*)");
  public static final AnyRawItemType<IMapItem<?>> ANY_MAP = new AnyRawItemType<>(
      IMapItem.class,
      "map(*)");
  public static final AnyRawItemType<IArrayItem<?>> ANY_ARRAY = new AnyRawItemType<>(
      IArrayItem.class,
      "array(*)");

  @NonNull
  private String signature;

  private AnyRawItemType(
      @NonNull Class<? extends I> itemClass,
      @NonNull String signature) {
    super(itemClass);
    this.signature = signature;
  }

  @Override
  public String toSignature() {
    return signature;
  }
}
