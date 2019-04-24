package com.yubico.objects.yhconcepts;

import lombok.NonNull;

/**
 * Class representing different concepts known to the device
 */
public class YHConcept {

    private final Object id;
    private final String name;

    /**
     * @param id   The concept ID
     * @param name The concept name
     */
    protected YHConcept(final Object id, final String name) {
        this.id = id;
        this.name = name;
    }

    protected Object getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    /**
     * Compares two concept objects
     *
     * @param other A YHConcept object
     * @return True of the two objects are of the same type and whose IDs are equals. False otherwise
     */
    public boolean equals(@NonNull final YHConcept other) {
        return equals(this, other);
    }

    /**
     * Compares two concept objects
     *
     * @param a A YHConcept object
     * @param b Another YHConcept object
     * @return True of the two objects are of the same type and whose IDs are equals. False otherwise
     */
    public static boolean equals(@NonNull final YHConcept a, @NonNull final YHConcept b) {
        if (!a.getClass().equals(b.getClass())) {
            return false;
        }
        return a.getId().equals(b.getId());
    }

}
